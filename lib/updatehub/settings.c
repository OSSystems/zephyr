#include <updatehub.h>
#include <settings/settings.h>

#define MAX_IP_SIZE 30

char *ip_buffer;
bool settings_initialized = false;

static int updatehub_settings_set(int argc, char **argv, void *val_ctx)
{
	int len = 0;

	if (argc == 1) {
		if (!strcmp(argv[0], "ip")) {
			len = settings_val_read_cb(val_ctx, &ip_buffer,
						   MAX_IP_SIZE);
		}
	}
}

static struct settings_handler updatehub_settings = {
	.name = "updatehub",
	.h_set = updatehub_settings_set,
};

int updatehub_settings_init()
{
	int ret;

	if (!settings_initialized) {
		ret = settings_subsys_init();
		if (ret != 0) {
			goto error;
		}

		ret = settings_register(&updatehub_settings);
		if (ret != 0) {
			goto error;
		}

		settings_initialized = true;
	}

error:
	return ret;
}
