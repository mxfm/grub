/*
 *  GRUB  --  GRand Unified Bootloader
 *  Copyright (C) 2003,2007,2010,2011,2019  Free Software Foundation, Inc.
 *
 *  GRUB is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  GRUB is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with GRUB.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <grub/cryptodisk.h>
#include <grub/dl.h>
#include <grub/err.h>
#include <grub/extcmd.h>
#include <grub/partition.h>
#include <grub/file.h>
#include <grub/gpt_partition.h>

GRUB_MOD_LICENSE ("GPLv3+");

#define GRUB_PLAINMOUNT_UUID        "00000000000000000000000000000000"
#define GRUB_PLAINMOUNT_CIPHER      "aes-cbc-essiv:sha256"
#define GRUB_PLAINMOUNT_DIGEST      "ripemd160"
#define GRUB_PLAINMOUNT_KEY_SIZE    256
#define GRUB_PLAINMOUNT_SECTOR_SIZE 512

static const struct grub_arg_option options[] =
  {
    /* TRANSLATORS: It's still restricted to this module only.  */
    {"hash", 'h', 0, N_("Password hash."), 0, ARG_TYPE_STRING},
    {"cipher", 'c', 0, N_("Password cipher."), 0, ARG_TYPE_STRING},
    {"offset", 'o', 0, N_("Device offset (512 bit blocks)."), 0, ARG_TYPE_INT},
    {"size", 'b', 0, N_("Size of device (512 byte blocks)."), 0, ARG_TYPE_INT},
    {"key-size", 's', 0, N_("Key size (in bits)."), 0, ARG_TYPE_INT},
    {"sector-size", 'z', 0, N_("Device sector size."), 0, ARG_TYPE_INT},
    {"keyfile", 'd', 0, N_("Keyfile/disk path."), 0, ARG_TYPE_STRING},
    {"keyfile-offset", 'O', 0, N_("Keyfile offset (512 bit blocks)."), 0, ARG_TYPE_INT},
    {"keyfile-size", 'l', 0, N_("Keyfile data size (in bits)."), 0, ARG_TYPE_INT},
    {0, 0, 0, 0, 0, 0}
  };

struct grub_plainmount_args
{
  char *key_data, *cipher, *mode, *hash, *keyfile;
  grub_size_t offset, size, key_size, sector_size, keyfile_offset, keyfile_size;
  grub_disk_t disk;
};
typedef struct grub_plainmount_args *grub_plainmount_args_t;

struct grub_plainmount_iterate_args
{
  char *uuid, *diskname;
};


/* Disk iterate callback */
static int grub_plainmount_scan_real (const char *name, void *data)
{
  int ret = 0;
  struct grub_plainmount_iterate_args *args = data;
  grub_disk_t source = NULL, disk = NULL;
  struct grub_partition *partition;
  struct grub_gpt_partentry entry;
  grub_gpt_part_guid_t *guid;
  /* UUID format: AAAABBBB-CCCC-DDDD-EEEE-FFFFFFFFFFFF + '\0' */
  char uuid[37] = "";

  source = grub_disk_open (name);
  if (!source)
      goto exit;
  if (!source->partition)
      goto exit;
  partition = source->partition;
  if (grub_strcmp (partition->partmap->name, "gpt") != 0)
      goto exit;
  disk = grub_disk_open (source->name);
  if (!disk)
      goto exit;
  if (grub_disk_read (disk, partition->offset, partition->index,
                      sizeof(entry), &entry) != GRUB_ERR_NONE)
      goto exit;
  guid = &entry.guid;
  grub_snprintf (uuid, sizeof(uuid),
                 "%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x",
                 grub_le_to_cpu32 (guid->data1),
                 grub_le_to_cpu16 (guid->data2),
                 grub_le_to_cpu16 (guid->data3),
                 guid->data4[0], guid->data4[1], guid->data4[2],
                 guid->data4[3], guid->data4[4], guid->data4[5],
                 guid->data4[6], guid->data4[7]);
  if (grub_strcasecmp (args->uuid, uuid) == 0)
    {
       args->diskname = grub_strdup (name);
       ret = 1;
    }

exit:
  if (source)
    grub_disk_close (source);
  if (disk)
    grub_disk_close (disk);
  return ret;
}


/* Get partition name from UUID */
static char* plainmount_get_diskname_from_uuid (char *uuid)
{
  struct grub_plainmount_iterate_args args = {uuid, NULL};
  if (grub_device_iterate (&grub_plainmount_scan_real, &args) == 1
      && args.diskname)
    return args.diskname;
  else
    return NULL;
}


/* Support use case: -d <UUID>/dir/keyfile */
static char*
plainmount_uuid_path_to_disk_path (char *uuid_path)
{
  char *slash = grub_strchr (uuid_path, '/');
  if (slash)
    {
      *slash = '\0';
      char *diskname = plainmount_get_diskname_from_uuid (uuid_path);
      if (!diskname)
      {
        *slash = '/';
        return NULL;
      }

      /* "(" + diskname + ")/" + path_after_first_slash + '\0' */
      int str_size = grub_strlen ("(")      +
                     grub_strlen (diskname) +
                     grub_strlen (")/")     +
                     grub_strlen (slash+1)  + 1; /* "some/path" */
      char *new_diskname = grub_zalloc (str_size);
      if (!new_diskname)
      {
        grub_free (diskname);
        *slash = '/';
        return NULL;
      }
      grub_snprintf (new_diskname, str_size, "(%s)/%s", diskname, slash+1);
      *slash = '/';
      return new_diskname;
    }
  else
      return plainmount_get_diskname_from_uuid (uuid_path);
}


/* Configure cryptodevice sector size (-z option), default - 512 byte */
static grub_err_t
plainmount_configure_sectors (grub_cryptodisk_t dev, grub_plainmount_args_t cargs)
{
  grub_disk_addr_t total_sectors;

  /* Check whether disk can be accessed */
  if (!cargs->size &&
        grub_disk_native_sectors (cargs->disk) == GRUB_DISK_SIZE_UNKNOWN)
      return grub_error (GRUB_ERR_BAD_DEVICE,
                         N_("cannot determine disk %s size"),
                         cargs->disk->name);

  /* cryptsetup allows only 512/1024/2048/4096 byte sectors */
  switch (cargs->sector_size)
    {
      case 512:
        dev->log_sector_size = 9;
        break;
      case 1024:
        dev->log_sector_size = 10;
        break;
      case 2048:
        dev->log_sector_size = 11;
        break;
      case 4096:
        dev->log_sector_size = 12;
        break;
      default:
        grub_error (GRUB_ERR_BAD_ARGUMENT,
                    N_("invalid sector size -z %"PRIuGRUB_SIZE
                       ", only 512/1024/2048/4096 are allowed"),
                    cargs->sector_size);
        grub_print_error ();
        return GRUB_ERR_BAD_ARGUMENT;
    }

  /* Offset is always given in terms of number of 512 byte sectors. */
  dev->offset_sectors = grub_divmod64 (cargs->offset*512,
                                       cargs->sector_size, NULL);

  if (cargs->size)
    total_sectors = cargs->size;
  else
    total_sectors = grub_disk_native_sectors (cargs->disk);

  /* Calculate disk sectors in terms of log_sector_size */
  total_sectors = grub_convert_sector (total_sectors, GRUB_DISK_SECTOR_BITS,
                                       dev->log_sector_size);
  dev->total_sectors = total_sectors - dev->offset_sectors;
  grub_dprintf ("plainmount", "log_sector_size=%d, total_sectors=%"PRIuGRUB_SIZE
                ", offset_sectors=%"PRIuGRUB_SIZE"\n", dev->log_sector_size,
                dev->total_sectors, dev->offset_sectors);
  return GRUB_ERR_NONE;
}


/* Hashes a password into a key and stores it with cipher. */
static grub_err_t
plainmount_configure_password (grub_cryptodisk_t dev, grub_plainmount_args_t cargs)
{
  const gcry_md_spec_t *hash = NULL;
  grub_uint8_t derived_hash[GRUB_CRYPTODISK_MAX_KEYLEN * 2], *dh = derived_hash;
  char *p;
  unsigned int round, i;
  unsigned int len, size;
  char *part = NULL;
  gcry_err_code_t code;

  /* Check hash */
  hash = grub_crypto_lookup_md_by_name (cargs->hash);
  if (!hash)
    return grub_error (GRUB_ERR_FILE_NOT_FOUND,
                       N_("couldn't load %s hash (perhaps a typo?)"),
                       cargs->hash);

  /* Check key size */
  if (cargs->key_size > GRUB_CRYPTODISK_MAX_KEYLEN ||
        hash->mdlen > GRUB_CRYPTODISK_MAX_KEYLEN)
          return grub_error (GRUB_ERR_BAD_ARGUMENT,
                             N_("invalid key size %"PRIuGRUB_SIZE
                                " (exceeds maximum %d bits)"),
                             cargs->key_size, GRUB_CRYPTODISK_MAX_KEYLEN * 8);
  dev->hash = hash;

  grub_disk_t source = cargs->disk;
  part = grub_partition_get_name (source->partition);
  grub_printf_ (N_("Enter passphrase for %s%s%s: "), source->name,
		    source->partition != NULL ? "," : "",
		    part != NULL ? part : N_("UNKNOWN"));
  grub_free (part);

  if (!grub_password_get (cargs->key_data, GRUB_CRYPTODISK_MAX_PASSPHRASE))
      grub_error (GRUB_ERR_BAD_ARGUMENT, N_("password not supplied"));

  /* Hack to support the "none" hash */
  if (dev->hash)
    len = dev->hash->mdlen;
  else
    len = cargs->key_size;

  p = grub_malloc (cargs->key_size + 2 + cargs->key_size / len);
  if (!p)
    return GRUB_ERR_OUT_OF_MEMORY;

  for (round = 0, size = cargs->key_size; size; round++, dh += len, size -= len)
    {
      for (i = 0; i < round; i++)
	p[i] = 'A';

      grub_strcpy (p + i, cargs->key_data);

      if (len > size)
	len = size;

      grub_crypto_hash (dev->hash, dh, p, grub_strlen (p));
    }
  grub_free (p);
  code = grub_cryptodisk_setkey (dev, derived_hash, cargs->key_size);
  grub_dprintf ("plainmount", "password crypto status is %d\n", code);
  if (code != GPG_ERR_NO_ERROR)
       return grub_error (GRUB_ERR_BAD_ARGUMENT,
                          N_("cannot set key from password. "
                             "Check keysize/hash/cipher options."));
  else
    return GRUB_ERR_NONE;
}


/* Read keyfile as a file */
static grub_err_t
plainmount_configure_keyfile (grub_cryptodisk_t dev, grub_plainmount_args_t cargs)
{
  grub_file_t keyfile;
  grub_err_t err;
  gcry_err_code_t code;

  keyfile = grub_file_open (cargs->keyfile, GRUB_FILE_TYPE_NONE);
  if (!keyfile)
    {
      /* Try to parse keyfile path as UUID path */
      char *real_path = plainmount_uuid_path_to_disk_path (cargs->keyfile);
      if (!real_path)
        {
          err = grub_error (GRUB_ERR_FILE_NOT_FOUND,
                            N_("cannot open keyfile %s as UUID or real path"),
                            cargs->keyfile);
          goto error;
        }
      grub_dprintf ("plainmount", "UUID %s converted to %s\n",
                    cargs->keyfile, real_path);
      keyfile = grub_file_open (real_path, GRUB_FILE_TYPE_NONE);
      if (!keyfile)
        {
          err = grub_error (GRUB_ERR_FILE_NOT_FOUND, N_("cannot open keyfile %s"),
                            real_path);
          goto error;
        }
    }

  if (grub_file_seek (keyfile, cargs->keyfile_offset) == (grub_off_t)-1)
    {
      err = grub_error (GRUB_ERR_FILE_READ_ERROR,
                        N_("cannot seek keyfile at offset %"PRIuGRUB_SIZE),
                        cargs->keyfile_offset);
      goto error;
    }

  if (cargs->keyfile_size)
    {
      if (cargs->keyfile_size > (keyfile->size - cargs->keyfile_offset))
        {
          err = grub_error (GRUB_ERR_BAD_ARGUMENT,
                            N_("Specified key size (%"PRIuGRUB_SIZE") is too small "
                               "for keyfile size (%"PRIuGRUB_SIZE") and offset (%"
                               PRIuGRUB_SIZE")"),
                            cargs->keyfile_size, keyfile->size,
                            cargs->keyfile_offset);
          goto error;
        }

      cargs->key_size = cargs->keyfile_size;
    }
  else
    cargs->key_size = keyfile->size - cargs->keyfile_offset;

  if (grub_file_read (keyfile, cargs->key_data, cargs->key_size) !=
       (grub_ssize_t) cargs->key_size)
     {
       err = grub_error (GRUB_ERR_FILE_READ_ERROR, N_("error reading key file"));
       goto error;
     }

  code = grub_cryptodisk_setkey (dev, (grub_uint8_t*) cargs->key_data,
                                 cargs->key_size);
  grub_dprintf ("plainmount", "keyfile: setkey() status %d\n", code);
  if (code != GPG_ERR_NO_ERROR)
    {
      err = grub_error (GRUB_ERR_BAD_ARGUMENT,
                        N_("cannot set key from keyfile %s. "
                           "Check keysize/cipher/hash options."),
                        cargs->keyfile);
      goto error;
    }
  else
    return GRUB_ERR_NONE;

error:
  grub_print_error ();
  return err;
}


/* Read keyfile as a disk segment */
static grub_err_t
plainmount_configure_keydisk (grub_cryptodisk_t dev, grub_plainmount_args_t cargs)
{
  grub_err_t err;
  grub_disk_t keydisk = NULL;
  char* keydisk_name = NULL;
  gcry_err_code_t code;
  grub_uint64_t total_sectors;

  keydisk_name = grub_file_get_device_name (cargs->keyfile);
  keydisk = keydisk_name ? grub_disk_open (keydisk_name) : NULL;
  if (!keydisk)
    {
      /* Try to parse keyfile path as UUID path */
      keydisk_name = plainmount_uuid_path_to_disk_path (cargs->keyfile);
      if (!keydisk_name)
      {
        err = grub_error (GRUB_ERR_BAD_ARGUMENT,
                          N_("unable to open disk %s as UUID or real path"),
                          cargs->keyfile);
        goto error;
      }
      keydisk = grub_disk_open (keydisk_name);
      if (!keydisk)
      {
        err = grub_error (GRUB_ERR_BAD_ARGUMENT, N_("unable to open disk %s"),
                         keydisk_name);
        goto error;
      }
    }

  total_sectors = grub_disk_native_sectors (keydisk);
  if (total_sectors == GRUB_DISK_SIZE_UNKNOWN)
    {
      err = grub_error (GRUB_ERR_BAD_DEVICE,
                        N_("unable to determine size of disk %s"),
                        keydisk_name);
      goto error;
    }
  total_sectors = grub_convert_sector (total_sectors, GRUB_DISK_SECTOR_BITS,
                                       keydisk->log_sector_size);

  if (GRUB_ERR_NONE != grub_disk_read (keydisk, 0, cargs->keyfile_offset,
                                       cargs->keyfile_size, cargs->key_data))
    {
      err = grub_error (GRUB_ERR_READ_ERROR, N_("failed to read from disk %s"),
                        keydisk_name);
      goto error;
    }
  code = grub_cryptodisk_setkey (dev, (grub_uint8_t*) cargs->key_data,
                                 cargs->key_size);
  grub_dprintf ("plainmount", "keydisk: setkey() status %d\n", code);
  if (code != GPG_ERR_NO_ERROR)
    {
      grub_error (GRUB_ERR_BAD_ARGUMENT,
                  N_("cannot set key from keydisk %s. "
                     "Check keysize/cipher/hash options."),
                  cargs->keyfile);
      goto error;
    }
  err = GRUB_ERR_NONE;
  goto cleanup;

error:
  grub_print_error ();

cleanup:
  grub_free (keydisk_name);
  if (keydisk)
    grub_disk_close (keydisk);
  return err;
}


/* Plainmount command entry point */
static grub_err_t
grub_cmd_plainmount (grub_extcmd_context_t ctxt, int argc, char **args)
{
  struct grub_arg_list *state = ctxt->state;
  struct grub_plainmount_args cargs = {0};
  grub_cryptodisk_t dev = NULL;
  char *diskname = NULL, *disklast = NULL;
  grub_size_t len;
  grub_err_t err = GRUB_ERR_BUG;
  const char *p = NULL;

  if (argc < 1)
    return grub_error (GRUB_ERR_BAD_ARGUMENT, N_("device name required"));

  /* Open SOURCE disk */
  diskname = args[0];
  len = grub_strlen (diskname);
  if (len && diskname[0] == '(' && diskname[len - 1] == ')')
    {
      disklast = &diskname[len - 1];
      *disklast = '\0';
      diskname++;
    }
  cargs.disk = grub_disk_open (diskname);
  if (!cargs.disk)
    {
      if (disklast)
        *disklast = ')';
      char *real_name = plainmount_get_diskname_from_uuid (diskname);
      if (real_name)
        {
          /* diskname must point to hdX,gptY, not to UUID */
          diskname = real_name;
          grub_dprintf ("plainmount", "deduced partition %s from UUID %s\n",
                        real_name, args[0]);
          cargs.disk = grub_disk_open (diskname);
          if (!cargs.disk)
            {
              err = grub_error (GRUB_ERR_BAD_ARGUMENT,
                                N_("cannot open disk %s specified as UUID %s"),
                                diskname, args[0]);
              goto error;
            }
        }
      else
        {
          err = grub_error (GRUB_ERR_BAD_ARGUMENT,
                            N_("cannot open disk %s by name or by UUID"), diskname);
          goto error;
        }
    }

  /* Process plainmount command arguments */
  cargs.hash = grub_strdup (state[0].set ? state[0].arg : GRUB_PLAINMOUNT_DIGEST);
  cargs.cipher = grub_strdup (state[1].set ? state[1].arg : GRUB_PLAINMOUNT_CIPHER);
  cargs.keyfile = state[6].set ? grub_strdup (state[6].arg) : NULL;
  if (!cargs.hash || !cargs.cipher || (!cargs.keyfile && state[6].set))
    {
      err = grub_error (GRUB_ERR_OUT_OF_MEMORY, "out of memory");
      goto error;
    }
  cargs.offset = state[2].set ? grub_strtoul (state[2].arg, &p, 0) : 0;
  if (state[2].set && (*p != '\0' || grub_errno != GRUB_ERR_NONE))
   {
     err = grub_error (GRUB_ERR_BAD_ARGUMENT, N_("unrecognized disk offset"));
     goto error;
   }
  cargs.size = (state[3].set ? grub_strtoul (state[3].arg, &p, 0) : 0) * 512;
  if (state[3].set && (*p != '\0' || grub_errno != GRUB_ERR_NONE))
   {
     err = grub_error (GRUB_ERR_BAD_ARGUMENT, N_("unrecognized disk size"));
     goto error;
   }
  cargs.key_size = (state[4].set ? grub_strtoul (state[4].arg, &p, 0) :
                                  GRUB_PLAINMOUNT_KEY_SIZE) / 8;
  if (state[4].set && (*p != '\0' || grub_errno != GRUB_ERR_NONE))
   {
     err = grub_error (GRUB_ERR_BAD_ARGUMENT, N_("unrecognized key size"));
     goto error;
   }
  cargs.sector_size = state[5].set ? grub_strtoul (state[5].arg, &p, 0) :
                                     GRUB_PLAINMOUNT_SECTOR_SIZE;
  if (state[5].set && (*p != '\0' || grub_errno != GRUB_ERR_NONE))
   {
     err = grub_error (GRUB_ERR_BAD_ARGUMENT, N_("unrecognized sector size"));
     goto error;
   }
  cargs.keyfile_offset = (state[7].set ? grub_strtoul (state[7].arg, &p, 0) : 0) * 512;
  if (state[7].set && (*p != '\0' || grub_errno != GRUB_ERR_NONE))
   {
     err = grub_error (GRUB_ERR_BAD_ARGUMENT, N_("unrecognized keyfile offset"));
     goto error;
   }
  cargs.keyfile_size = (state[8].set ? grub_strtoul (state[8].arg, &p, 0) : 0) / 8;
  if (state[8].set && (*p != '\0' || grub_errno != GRUB_ERR_NONE))
   {
     err = grub_error (GRUB_ERR_BAD_ARGUMENT, N_("unrecognized keyfile size"));
     goto error;
   }

  /* Check cipher mode */
  cargs.mode = grub_strchr (cargs.cipher,'-');
  if (!cargs.mode)
    {
      err = grub_error (GRUB_ERR_BAD_ARGUMENT, N_("invalid cipher mode"));
      goto error;
    }
  else
    *cargs.mode++ = 0;

  /* Check keyfile size */
  if (cargs.keyfile && cargs.keyfile_size > GRUB_CRYPTODISK_MAX_KEYLEN)
    {
      err = grub_error (GRUB_ERR_OUT_OF_RANGE,
                        N_("key file size exceeds maximum size (%d)"),
                        GRUB_CRYPTODISK_MAX_KEYLEN);
      goto error;
    }

  /* Create cryptodisk object and test cipher */
  dev = grub_zalloc (sizeof *dev);
  if (!dev)
    {
      err = grub_error (GRUB_ERR_OUT_OF_MEMORY, N_("out of memory"));
      goto error;
    }

  /* Check cipher */
  if (grub_cryptodisk_setcipher (dev, cargs.cipher, cargs.mode) != GRUB_ERR_NONE)
    {
      err = grub_error (GRUB_ERR_BAD_ARGUMENT, N_("invalid cipher %s"), cargs.cipher);
      goto error;
    }

  /* Warn if hash and keyfile are both provided */
  if (cargs.keyfile && state[0].arg)
    grub_printf_ (N_("warning: hash parameter is ignored if keyfile is specified\n"));

  /* Warn if key file args are provided without key file */
  if (!state[6].set && (state[7].set || state[8].set))
    grub_printf_ (N_("warning: keyfile offset (-O) and size (-l) arguments "
                     "are ignored without keyfile (-d)\n"));

  /* Warn if hash was not set */
  if (!state[0].set && !cargs.keyfile)
    grub_printf_ (N_("warning: using password and hash is not set, using default %s\n"),
                  cargs.hash);

  /* Warn if cipher was not set */
  if (!state[1].set)
    grub_printf_ (N_("warning: cipher not set, using default %s\n"),
                  GRUB_PLAINMOUNT_CIPHER);

  /* Warn if key size was not set */
  if (!state[4].set)
    grub_printf_ (N_("warning: key size not set, using default %"PRIuGRUB_SIZE" bits\n"),
                  cargs.key_size * 8);

  err = plainmount_configure_sectors (dev, &cargs);
  if (err != GRUB_ERR_NONE)
    goto error;

  grub_dprintf ("plainmount",
              "parameters: cipher=%s, hash=%s, key_size=%"PRIuGRUB_SIZE", keyfile=%s, "
              "keyfile offset=%"PRIuGRUB_SIZE", key file size=%"PRIuGRUB_SIZE"\n",
              cargs.cipher, cargs.hash, cargs.key_size,
              cargs.keyfile ? cargs.keyfile : NULL,
              cargs.keyfile_offset, cargs.keyfile_size);

  dev->modname = "plainmount";
  dev->source_disk = cargs.disk;
  grub_memcpy (dev->uuid, GRUB_PLAINMOUNT_UUID, sizeof (dev->uuid));
  COMPILE_TIME_ASSERT (sizeof (dev->uuid) >= sizeof (GRUB_PLAINMOUNT_UUID));

  /* For password or keyfile */
  cargs.key_data = grub_zalloc (GRUB_CRYPTODISK_MAX_PASSPHRASE);
  if (!cargs.key_data)
    {
      err = grub_error (GRUB_ERR_OUT_OF_MEMORY, N_("out of memory"));
      goto error;
    }

  /* Configure keyfile/keydisk/password */
  if (cargs.keyfile)
    if (grub_strchr (cargs.keyfile, '/'))
      err = plainmount_configure_keyfile (dev, &cargs);
    else
      err = plainmount_configure_keydisk (dev, &cargs);
  else /* password */
    err = plainmount_configure_password (dev, &cargs);
  if (err != GRUB_ERR_NONE)
    goto error;

  err = grub_cryptodisk_insert (dev, diskname, cargs.disk);
  if (err == GRUB_ERR_NONE)
    {
      grub_printf_ ("disk %s mounted as crypto%"PRIuGRUB_SIZE" in plain mode.\n",
                     dev->source, dev->id);
      return err;
    }
  else
      grub_printf_ (N_("cannot initialize cryptodisk. "
                    "Check cipher/key size/hash arguments\n"));

error:
  grub_free (cargs.hash);
  grub_free (cargs.cipher);
  grub_free (cargs.keyfile);
  grub_free (cargs.key_data);
  if (cargs.disk)
    grub_disk_close (cargs.disk);
  return err;
}

static grub_extcmd_t cmd;
GRUB_MOD_INIT (plainmount)
{
  cmd = grub_register_extcmd ("plainmount", grub_cmd_plainmount, 0,
			      N_("[-h hash] [-c cipher] [-o offset] [-s size] "
			      "[-k key-size] [-z sector-size] [-d keyfile] "
			      "[-O keyfile offset] [-l keyfile-size] <SOURCE>"),
			      N_("Open partition encrypted in plain mode."), options);
}

GRUB_MOD_FINI (plainmount)
{
  grub_unregister_extcmd (cmd);
}
