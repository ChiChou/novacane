#include <stdio.h>
#include <string.h>

#include <libimobiledevice/libimobiledevice.h>
#include <libimobiledevice/lockdown.h>

int main(int argc, char *argv[]) {
  if (argc == 2 && (strcmp(argv[1], "-h") == 0 || strcmp(argv[1], "--help") == 0)) {
    printf("Usage: %s [uuid]\n", argv[0]);
    return 0;
  }

  const char *udid = argc == 2 ? argv[1] : NULL;
  idevice_t device = NULL;
  enum idevice_options lookup_opts = IDEVICE_LOOKUP_USBMUX | IDEVICE_LOOKUP_NETWORK;

  if (idevice_new_with_options(&device, udid, lookup_opts) != IDEVICE_E_SUCCESS) {
		if (udid) {
			fprintf(stderr, "ERROR: Device \"%s\" not found!\n", udid);
		} else {
			fprintf(stderr, "ERROR: No device found!\n");
		}
		return -1;
	}

  lockdownd_client_t lockdown;
	lockdownd_client_new_with_handshake(device, &lockdown, NULL);
  lockdownd_service_descriptor_t svc = NULL;
	if (lockdownd_start_service(lockdown, "com.apple.webinspector", &svc) != LOCKDOWN_E_SUCCESS) {
		lockdownd_client_free(lockdown);
		idevice_free(device);
		fprintf(stderr, "ERROR: Could not start the webinspectord service. \n");
		return -1;
	}
	lockdownd_client_free(lockdown);

  fprintf(stderr, "successfully connected to webinspector\n");
}