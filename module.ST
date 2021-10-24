typedef struct slowboot_tinfoil {
	struct kstat *st;
	slowboot_validation_item validation_items[16843];
	int failures;
} slowboot_tinfoil;
