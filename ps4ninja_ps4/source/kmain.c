#undef _SYS_CDEFS_H_
#undef _SYS_TYPES_H_
#undef _SYS_PARAM_H_
#undef _SYS_MALLOC_H_

#define _XOPEN_SOURCE 700
#define __BSD_VISIBLE 1
#define _KERNEL
#define _WANT_UCRED
#include <sys/cdefs.h>
#include <sys/types.h>
#include <sys/param.h>
#include <sys/kernel.h>
#include <sys/systm.h>
#include <sys/malloc.h>
#include <sys/proc.h>
#include <sys/user.h>
#include <sys/uio.h>
#include <sys/ptrace.h>

#undef offsetof
#include <kernel.h>
#include <ps4/kernel.h>
//#inlude "ps4ninja.h"

#include "kmain.h"
int (*printfkernel)(const char *fmt, ...) = (void *)0xFFFFFFFF8246E340;
int (*Copyout)(const void *kaddr, void *uaddr, size_t len) = (void*)0xFFFFFFFF82613C40;
int(*Copyin)(const void *udaddr, void *kaddr, size_t len) = (void*)0xFFFFFFFF82613CC0;
typedef int64_t (*kernel_memset)(void* ptr, int value, size_t num);
typedef int64_t (*ksceSblSsDecryptSealkedKey)(void* sealedKey, void* decryptedKey);

struct ps4ninja_read_kmem_uap
{
	unsigned long long kernel_addr;
	unsigned long long user_addr;
	unsigned long long len;
};

struct ps4ninja_write_kmem_uap
{
	unsigned long long kernel_addr;
	unsigned long long user_addr;
	unsigned long long len;
};

ksceSblSsDecryptSealkedKey KsceSblSsDecryptSealkedKey =  ((int64_t (*)(void * ptr, void * ptr2))0xFFFFFFFF827B0FA0);
kernel_memset Kmemset =  ((int64_t (*)(void * ptr, int value, size_t num))0xFFFFFFFF8261EB30);

int kDecryptSealedKey(struct thread *td, void * uap)
{
	void * uSealedKey = uap;
	struct malloc_type *mt = ps4KernelDlSym("M_TEMP");
	int keySize = 0x60;
	void * kSKey = malloc(keySize, mt, M_ZERO | M_WAITOK);
	void * dKey = malloc(0x80, mt, M_ZERO | M_WAITOK);

	copyin(uSealedKey, kSKey, keySize);

	int ret = KsceSblSsDecryptSealkedKey(kSKey, dKey);

	printfkernel("Returning from sceSblSsDecryptedSealedKey with ret: %d\n", ret);
	ps4KernelThreadSetReturn(td, ret);

	copyout(dKey, (uint8_t*)uSealedKey + 0x60, 0x20);

	free(dKey, mt);
	free(kSKey, mt);

	return ret;
}


// Decrypted key must be a buffer of 0x20 bytes
void getEAPPartitionKey()
{
	void(*Bzero)(void *buf, size_t len) = (void *)0xFFFFFFFF82613B00;
	void(*icc_nvs_read)(size_t id, size_t no, size_t offset, size_t len, unsigned char *buff) = (void *)0xFFFFFFFF82639CD0;
	void(*sceSblGetEAPInternalPartitionKey)(unsigned char *encBuffer, unsigned char *decBzffer) = (void*)0xFFFFFFFF827B1B00;

	struct malloc_type *mt = ps4KernelDlSym("M_TEMP");

	unsigned char *encNVSKeyBuffer = (unsigned char*)0xFFFFFFFF836C0000;// malloc(0x70, mt, M_ZERO | M_WAITOK);
	unsigned char *decryptedKey = malloc(0x20, mt, M_ZERO | M_WAITOK);
	Bzero(encNVSKeyBuffer, 0x70);
	Bzero(decryptedKey, 0x20);

	const unsigned char nvs_00_04_bin[96] = {
		0xCE, 0xED, 0x63, 0x10, 0x67, 0xD3, 0xA3, 0xBF, 0xCC, 0xF9, 0x9A, 0x58, 0x0A, 0xE3, 0x6F, 0x3D,
		0x1E, 0x68, 0xCA, 0x34, 0x37, 0xA2, 0x74, 0xE2, 0xD9, 0xDD, 0x03, 0x50, 0xF5, 0x4C, 0xF5, 0xAE,
		0x18, 0x2E, 0x78, 0xB6, 0x8C, 0xC7, 0xF1, 0xDF, 0xD6, 0x78, 0x6A, 0x75, 0xEB, 0xDE, 0xD2, 0x30,
		0x20, 0x07, 0x59, 0xB4, 0xCB, 0x16, 0x4F, 0xC8, 0x02, 0x3A, 0x7D, 0x27, 0x27, 0x7D, 0x7E, 0xC3,
		0xF9, 0x6F, 0x7B, 0x6D, 0x0E, 0x74, 0x13, 0x62, 0x65, 0x1D, 0x05, 0x5F, 0x8B, 0x46, 0xDB, 0x8B,
		0x50, 0x98, 0xC9, 0xFF, 0x09, 0xB8, 0x97, 0x47, 0x26, 0xF9, 0xDA, 0x20, 0xC1, 0x44, 0x23, 0xD0
	};


	printf("\nGetting EAP Key\n");
	printf("\nencKey: 0x%llx\n", encNVSKeyBuffer);
	printf("decKey: 0x%llx\n", decryptedKey);

	for (int i = 0; i < 96; i++)
		encNVSKeyBuffer[i] = nvs_00_04_bin[i];

	// Read encrypted key from NVS
	//icc_nvs_read(0, 4, 0x200, 0x60, encNVSKeyBuffer);
	printf("icc_nvs_read: ");

	for (int i = 0; i < 0x60; i++)
	{
		if (encNVSKeyBuffer[i] < 0x10)
			printf("0x0%x ", encNVSKeyBuffer[i]);
		else
			printf("0x%x ", encNVSKeyBuffer[i]);
	}

	// Let SAMU decrypt the key
	sceSblGetEAPInternalPartitionKey(encNVSKeyBuffer, decryptedKey);

	printf("\nsceSblGetEAPInternalPartitionKey: ");

	for (int i = 0; i < 0x20; i++)
	{
		if (decryptedKey[i] < 0x10)
			printf("0x0%x ", decryptedKey[i]);
		else
			printf("0x%x ", decryptedKey[i]);
	}

	printf("\n");

	return;
}


int setsysucred(struct thread *td, void * uap)
{
	ps4KernelProtectionWriteDisable();
	
	
	// Allow self decryption		
	// sceSblAuthMgrIsLoadable		
	*(uint8_t *)(0xFFFFFFFF827C67A0) = 0x31;
	*(uint8_t *)(0xFFFFFFFF827C67A1) = 0xC0;
	*(uint8_t *)(0xFFFFFFFF827C67A2) = 0xC3;
	// allow mapping selfs - place 2
	*(uint8_t *)(0xFFFFFFFF825F5200) = 0xB8;
	*(uint8_t *)(0xFFFFFFFF825F5201) = 0x01;
	*(uint8_t *)(0xFFFFFFFF825F5202) = 0x00;
	*(uint8_t *)(0xFFFFFFFF825F5203) = 0x00;
	*(uint8_t *)(0xFFFFFFFF825F5204) = 0x00;
	*(uint8_t *)(0xFFFFFFFF825F5205) = 0xC3;
	// allow mapping selfs - place 3
	*(uint8_t *)(0xFFFFFFFF825F5210) = 0xB8;
	*(uint8_t *)(0xFFFFFFFF825F5211) = 0x01;
	*(uint8_t *)(0xFFFFFFFF825F5212) = 0x00;
	*(uint8_t *)(0xFFFFFFFF825F5213) = 0x00;
	*(uint8_t *)(0xFFFFFFFF825F5214) = 0x00;
	*(uint8_t *)(0xFFFFFFFF825F5215) = 0xC3;
	/*
	// sceSblAuthMgrAuthHeader - allow elf header check
	((uint8_t *)0xFFFFFFFF827C6CC2)[0] = 0x90; //89
	((uint8_t *)0xFFFFFFFF827C6CC2)[1] = 0x90; //89
	((uint8_t *)0xFFFFFFFF827C6CC2)[2] = 0x90; //89
	((uint8_t *)0xFFFFFFFF827C6CC2)[3] = 0x90; //89
	((uint8_t *)0xFFFFFFFF827C6CC2)[4] = 0x90; //89
	((uint8_t *)0xFFFFFFFF827C6CC2)[5] = 0x90; //89

	

	// sceSblAuthMgrAuthHeader - Ignore _sceSblAuthMgrCheckElfHeader result
	((uint8_t *)0xFFFFFFFF827C6CFF)[0] = 0xEB;

	// sceSblAuthMgrAuthHeader - Ignore _sceSblAuthMgrVerifySelfHeader result
	((uint8_t *)0xFFFFFFFF827C6E9E)[0] = 0xEB;
	
	//allow elf header check
	FFFFFFFF827C6C82 = 45
	// Dont call samu when loading elf segments
	FFFFFFFF827C6E93 = 90 90 90 90 90
	// Elf does not need to be decrypted (this breaks selfs)
	FFFFFFFF827CA018 = EB
	// sceSblAuthMgrAuthHeader - Ignore _sceSblAuthMgrVerifySelfHeader result
	FFFFFFFF827C6E9E = EB

	// _sceSblAuthMgrVerifySelfHeader - Ignore samu call
	((uint8_t *)0xFFFFFFFF827C9A0F)[0] = 0x90;
	((uint8_t *)0xFFFFFFFF827C9A0F)[1] = 0x90;
	
	((uint8_t *)0xFFFFFFFF827C9A20)[0] = 0x90;
	((uint8_t *)0xFFFFFFFF827C9A20)[1] = 0xE9;	
	*/
	// Restore write protection
	ps4KernelProtectionWriteEnable();

	
	void *td_ucred = *(void **)(((char *)td) + 304); // p_ucred == td_ucred
	
	// sceSblACMgrIsSystemUcred
	uint64_t *sonyCred = (uint64_t *)(((char *)td_ucred) + 96);
	*sonyCred = 0xffffffffffffffff;
	
	// sceSblACMgrGetDeviceAccessType
	uint64_t *sceProcType = (uint64_t *)(((char *)td_ucred) + 88);
	*sceProcType = 0x3801000000000013; // Max access
	
	// sceSblACMgrHasSceProcessCapability
	uint64_t *sceProcCap = (uint64_t *)(((char *)td_ucred) + 104);
	*sceProcCap = 0xffffffffffffffff; // Sce Process

	return 0;
}

void ps4ninja_kernel_disable_userland_aslr()
{
	// Disable write protection
	ps4KernelProtectionWriteDisable();

	*(uint8_t *)0xFFFFFFFF82404630 = 0x31;
	*(uint8_t *)0xFFFFFFFF82404631 = 0xC0;
	*(uint8_t *)0xFFFFFFFF82404632 = 0xC3;

	// Restore write protection
	ps4KernelProtectionWriteEnable();
}

void ps4ninja_kernel_enable_userland_aslr()
{
	// Disable write protection
	ps4KernelProtectionWriteDisable();

	*(uint8_t *)0xFFFFFFFF82404630 = 0x55;
	*(uint8_t *)0xFFFFFFFF82404631 = 0x48;
	*(uint8_t *)0xFFFFFFFF82404632 = 0x89;

	// Restore write protection
	ps4KernelProtectionWriteEnable();
}

void ps4ninja_kernel_disable_rwx_mapping()
{
	// Disable write protection
	ps4KernelProtectionWriteDisable();

	*(uint8_t *)0xFFFFFFFF825AB7BC = 0x03;
	*(uint8_t *)0xFFFFFFFF825AB7E8 = 0x03;

	// Restore write protection
	ps4KernelProtectionWriteEnable();
}

void ps4ninja_kernel_enable_rwx_mapping()
{
	//getEAPPartitionKey();

	// Disable write protection
	ps4KernelProtectionWriteDisable();

	*(uint8_t *)0xFFFFFFFF825AB7BC = 0x07;
	*(uint8_t *)0xFFFFFFFF825AB7E8 = 0x07;

	// Restore write protection
	ps4KernelProtectionWriteEnable();
}

void ps4ninja_kernel_read_kmem(struct thread *td, struct ps4ninja_read_kmem_uap *uap)
{
	printf("ps4ninja_kernel_read_kmem() -> transferring %llu bytes from 0x%llx to 0x%llx\n", uap->len, uap->kernel_addr, uap->user_addr);
	Copyout((void*)uap->kernel_addr, (void*)uap->user_addr, uap->len);
}

void ps4ninja_kernel_write_kmem(struct thread *td, struct ps4ninja_write_kmem_uap *uap)
{
	printf("ps4ninja_kernel_write_kmem() -> transferring %llu bytes from 0x%llx to 0x%llx\n", uap->len, uap->user_addr, uap->kernel_addr);
	unsigned char buff[4096];
	Copyin((void*)uap->user_addr, (void*)buff, uap->len);

	unsigned char *kmem = (unsigned char*)uap->kernel_addr;

	// Disable write protection
	ps4KernelProtectionWriteDisable();

	for (int i = 0; i < uap->len; i++)
		kmem[i] = buff[i];

	// Restore write protection
	ps4KernelProtectionWriteEnable();
}


