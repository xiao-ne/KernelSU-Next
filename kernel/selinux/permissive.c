// SPDX-License-Identifier: GPL-2.0
/*
 * Keep the manager's "SELinux permissive" switch alive across reboots.
 *
 * The manager only performs a one-shot setenforce 0 when the switch is
 * flipped, and nothing replays it during boot, so the phone silently goes
 * back to enforcing after every reboot. Remember the last observed mode in
 * /data/adb/ksu/.permissive and re-apply it once /data is mounted.
 */
#include <linux/cred.h>
#include <linux/delay.h>
#include <linux/err.h>
#include <linux/fs.h>
#include <linux/jiffies.h>
#include <linux/kernel.h>
#include <linux/namei.h>
#include <linux/slab.h>
#include <linux/workqueue.h>

#include "klog.h"
#include "ksu.h"
#include "selinux.h"
#include "permissive.h"

#define KSU_PERMISSIVE_FLAG "/data/adb/ksu/.permissive"
#define KSU_DATA_DIR "/data/adb"

/* How often the current mode is sampled, in milliseconds. */
#define KSU_PERMISSIVE_POLL_MS 3000
/* Give /data about 200 seconds to show up before giving up. */
#define KSU_PERMISSIVE_BOOT_TRIES 200

static struct delayed_work ksu_permissive_work;
static bool ksu_permissive_boot_done;
static bool ksu_permissive_last_enforce = true;
static unsigned int ksu_permissive_boot_tries;

static int ksu_permissive_read_flag(char *buf, size_t len)
{
	struct file *fp;
	loff_t off = 0;
	ssize_t ret;
	const struct cred *saved;

	saved = override_creds(ksu_cred);
	fp = filp_open(KSU_PERMISSIVE_FLAG, O_RDONLY, 0);
	if (IS_ERR(fp)) {
		ret = PTR_ERR(fp);
		revert_creds(saved);
		return ret;
	}
	ret = kernel_read(fp, buf, len, &off);
	filp_close(fp, 0);
	revert_creds(saved);

	return ret;
}

static void ksu_permissive_store_flag(bool enforce)
{
	struct file *fp;
	loff_t off = 0;
	char value = enforce ? '1' : '0';
	const struct cred *saved;

	saved = override_creds(ksu_cred);
	fp = filp_open(KSU_PERMISSIVE_FLAG, O_WRONLY | O_CREAT | O_TRUNC, 0600);
	if (IS_ERR(fp)) {
		pr_err("permissive: cannot open %s: %ld\n", KSU_PERMISSIVE_FLAG,
		       PTR_ERR(fp));
		revert_creds(saved);
		return;
	}
	if (kernel_write(fp, &value, 1, &off) != 1)
		pr_err("permissive: write flag failed\n");
	filp_close(fp, 0);
	revert_creds(saved);
}

static bool ksu_data_ready(void)
{
	struct path path;

	if (kern_path(KSU_DATA_DIR, LOOKUP_DIRECTORY, &path))
		return false;
	path_put(&path);
	return true;
}

static void ksu_permissive_tick(struct work_struct *work)
{
	char buf[8] = { 0 };
	bool enforce_now;

	if (!ksu_permissive_boot_done) {
		if (!ksu_data_ready()) {
			if (++ksu_permissive_boot_tries >
			    KSU_PERMISSIVE_BOOT_TRIES) {
				pr_info("permissive: /data never showed up, skip restore\n");
				ksu_permissive_boot_done = true;
				ksu_permissive_last_enforce = getenforce();
			}
			goto rearm;
		}

		if (ksu_permissive_read_flag(buf, sizeof(buf) - 1) > 0) {
			if (buf[0] == '0') {
				if (getenforce()) {
					pr_info("permissive: restoring permissive mode\n");
					setenforce(false);
				}
			} else {
				pr_info("permissive: stored mode is enforcing\n");
			}
		}

		ksu_permissive_boot_done = true;
		ksu_permissive_last_enforce = getenforce();
		pr_info("permissive: boot restore done, enforcing=%d\n",
			ksu_permissive_last_enforce);
		goto rearm;
	}

	enforce_now = getenforce();
	if (enforce_now != ksu_permissive_last_enforce) {
		ksu_permissive_last_enforce = enforce_now;
		pr_info("permissive: mode changed to %s, persisting\n",
			enforce_now ? "enforcing" : "permissive");
		ksu_permissive_store_flag(enforce_now);
	}

rearm:
	schedule_delayed_work(&ksu_permissive_work,
			      msecs_to_jiffies(ksu_permissive_boot_done ?
						       KSU_PERMISSIVE_POLL_MS :
						       1000));
}

void ksu_permissive_persist_init(void)
{
	ksu_permissive_last_enforce = getenforce();
	INIT_DELAYED_WORK(&ksu_permissive_work, ksu_permissive_tick);
	schedule_delayed_work(&ksu_permissive_work, msecs_to_jiffies(2000));
	pr_info("permissive: persist worker started, enforcing=%d\n",
		ksu_permissive_last_enforce);
}
