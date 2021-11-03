GLOWSLAYER Explicit Access Control System

Simple
Auditable
Absolute

All code/files are GPLv2 or newer with personal reservations to change them for separate use.
For systems where system integrity is paramount and simplicity of validation matters
take matters into your own hands.

Four Basic Components
	Tinfoil: 	initramfs validation
	Slowboot: 	installed binary/module/file validation
	Snarf: 		pre execute checks
	LD_master: 	pre open checks

Wall your own garden

Prerequisites:
	kernel source
	kernel config
	ability to compile kernel, modules, install and boot from it
	a system that is already configured with the software on it that you want
		This will be suffering and pain on a system that you update all the time
		and install a bunch of software on. This is meant to be used to run VMs, a server,
		a router or something where once you set it up you want it to become nearly
		immutable
	limited package selection. This will dynamically hardcode a bunch of arrays into the kernel
		there is no way current way to easily patch the system without going through the entire
		process again
	Some usefull books that might help you implement this on your system:
		The Linux Programming Interface - Michael Kerrisk
		Linux Kernel Programming - Kaiwan N Billmoria
		
Usefull Commands:
	cmd_signkernel: sudo sbsign --key ~/my_signing_key.priv --cert ~/MOK.pem /boot/vmlinuz-5.14.13-tinfoil+ --output /boot/vmlinuz-5.14.13-tinfoil+.signed
	cmd_installsignedkernel sudo cp /boot/vmlinuz-5.14.13-tinfoil+.signed /boot/vmlinuz-5.14.13-tinfoil+
	
	
		
Step:
	compile kernel as is with your configuration
		make bzImage
		make modules
		sudo make install
		sudo make modules_install
		
Step:
	make sure you have everything that you need installed
		
Step:
	compile kernel module
		from root directory of repo:
			#This may take a significant amount of time
			sudo ./generate_module_params.py > slowboot.c
			make all
			sudo make install
			
Step:
	make sure the module is in the initramfs and will load on boot
		TODO, just google it for now
		
??? You have now configured Slowboot

Step
	move to the linux source tree and open init/main.c
	install the function_patches.c patch
	#This may take a significant amount of time
	sudo ./generate_init_params.py /boot/initramfs-5.14.13+.img > tinfoil.c
	copy the code in tinfoil.c (you will have to remove the MODULE 
		stuff and the exit method and the atribute on the init method
		make sure it is above the patched method
		
??? you have now configured tinfoil

TODO: docs for Snarf/LD master
	
