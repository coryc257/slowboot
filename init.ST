typedef struct slowboot_tinfoil {
	struct kstat *st;
	slowboot_validation_item validation_items[33];
	int failures;
} slowboot_tinfoil;
