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

GRUB_MOD_LICENSE ("GPLv3+");

static const struct grub_arg_option options[] =
  {
    /* TRANSLATORS: It's still restricted to this module only.  */
    {"hash", 'h', 0, N_("Password hash"), 0, ARG_TYPE_STRING},
    {"cipher", 'c', 0, N_("Password cipher"), 0, ARG_TYPE_STRING},
    {"offset", 'o', 0, N_("Device offset"), 0, ARG_TYPE_STRING},
    {"disk-size", 'b', 0, N_("Device size"), 0, ARG_TYPE_STRING},
    {"key-size", 's', 0, N_("Key size (in bits)"), 0, ARG_TYPE_INT},
    {"sector-size", 'S', 0, N_("Device sector size"), 0, ARG_TYPE_INT},
    {"password", 'p', 0, N_("Password (key)"), 0, ARG_TYPE_STRING},
    {"keyfile", 'd', 0, N_("Keyfile/disk path"), 0, ARG_TYPE_STRING},
    {"keyfile-offset", 'O', 0, N_("Keyfile offset."), 0, ARG_TYPE_STRING},
    {0, 0, 0, 0, 0, 0}
  };

struct grub_plainmount_args
{
  char *key_data, *cipher, *mode, *hash, *keyfile;
  grub_size_t offset, size, key_size, sector_size, keyfile_offset;
  grub_disk_t disk;
};
typedef struct grub_plainmount_args *grub_plainmount_args_t;


/* Cryptodisk setkey() function wrapper */
static grub_err_t
plainmount_setkey (grub_cryptodisk_t dev, grub_uint8_t *data,
                   grub_size_t size)
{
  gcry_err_code_t code = grub_cryptodisk_setkey (dev, data, size);
  if (code != GPG_ERR_NO_ERROR)
    {
      grub_dprintf ("plainmount", "password crypto status is %d\n", code);
      return grub_error (GRUB_ERR_BAD_ARGUMENT,
                         N_("cannot set key from password. "
                            "Check keysize/hash/cipher options."));
    }
  return GRUB_ERR_NONE;
}


/* Parse disk size suffix */
static grub_size_t plainmount_parse_suffix (char *arg)
{
  const char *p = NULL;
  grub_errno = GRUB_ERR_NONE;
  grub_size_t val = grub_strtoull (arg, &p, 0);
  switch (*p)
    {
      case 'K':
      case 'k':
        val = val * 1024;
        break;
      case 'M':
      case 'm':
        val = val * 1024*1024;
        break;
      case 'G':
      case 'g':
        val = val * 1024*1024*1024;
        break;
      case '\0':
        break;
      default:
        val = (grub_size_t) -1;
    }
  return val;
}

/* Configure cryptodisk uuid */
static void plainmount_set_uuid (grub_cryptodisk_t dev)
{
  grub_size_t pos = 0;
  static const char *uuid = "00000000-0000-0000-0000-000000000000";
  grub_snprintf (dev->uuid, sizeof (dev->uuid)-1, "%32lu", dev->id+1);
  while (dev->uuid[pos++] == ' ');
  grub_memcpy (dev->uuid, uuid, pos-1);
  COMPILE_TIME_ASSERT (sizeof (dev->uuid) >= sizeof (uuid));
}


/* Configure cryptodevice sector size (-S option) */
static grub_err_t
plainmount_configure_sectors (grub_cryptodisk_t dev, grub_plainmount_args_t cargs)
{
  grub_disk_addr_t total_sectors;

  /* cryptsetup allows only 512/1024/2048/4096 byte sectors */
  if (!(cargs->sector_size == 512 || cargs->sector_size == 1024 ||
        cargs->sector_size == 2048 || cargs->sector_size == 4096))
        return grub_error (GRUB_ERR_BAD_ARGUMENT,
                           N_("invalid sector size -S %"PRIuGRUB_SIZE
                              ", only 512/1024/2048/4096 are allowed"),
                           cargs->sector_size);
  switch (cargs->sector_size)
    {
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
        dev->log_sector_size = 9;
    }

  /* Convert size to sectors */
  if (cargs->size)
    total_sectors = cargs->size / 512;
  else
    {
      total_sectors = grub_disk_native_sectors (cargs->disk);
      if (total_sectors == GRUB_DISK_SIZE_UNKNOWN)
        return grub_error (GRUB_ERR_BAD_DEVICE,
                           N_("cannot determine disk %s size"),
                           cargs->disk->name);
    }
  total_sectors = grub_convert_sector (total_sectors, GRUB_DISK_SECTOR_BITS,
                                       dev->log_sector_size);
  if (total_sectors == 0)
    return grub_error (GRUB_ERR_BAD_DEVICE,
                       N_("cannot determine disk size"));
  dev->offset_sectors = grub_divmod64 (cargs->offset, cargs->sector_size, NULL);
  if (total_sectors <= dev->offset_sectors)
    return grub_error (GRUB_ERR_BAD_ARGUMENT,
                       N_("specified disk offset is larger than disk size"));
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

  /* Check hash */
  hash = grub_crypto_lookup_md_by_name (cargs->hash);
  if (!hash)
    return grub_error (GRUB_ERR_FILE_NOT_FOUND,
                       N_("couldn't load %s hash (perhaps a typo?)"),
                       cargs->hash);

  if (hash->mdlen > GRUB_CRYPTODISK_MAX_KEYLEN)
        return grub_error (GRUB_ERR_BAD_ARGUMENT,
                           N_("hash length %"PRIuGRUB_SIZE
                              " exceeds maximum %d bits"),
                           hash->mdlen, GRUB_CRYPTODISK_MAX_KEYLEN * 8);
  dev->hash = hash;

  /* Hack to support the "none" hash */
  if (dev->hash)
    len = dev->hash->mdlen;
  else
    len = cargs->key_size;

  /* Option -p was not set */
  if (cargs->key_data[0] == '\0')
  {
    grub_disk_t source = cargs->disk;
    char *part = grub_partition_get_name (source->partition);
    grub_printf_ (N_("Enter passphrase for %s%s%s: "), source->name,
                  source->partition != NULL ? "," : "",
                  part != NULL ? part : N_("UNKNOWN"));
    grub_free (part);

    if (!grub_password_get (cargs->key_data, GRUB_CRYPTODISK_MAX_PASSPHRASE-1))
        grub_error (GRUB_ERR_BAD_ARGUMENT, N_("password not supplied"));
  }

  p = grub_malloc (cargs->key_size + 2 + cargs->key_size / len);
  if (!p)
    return GRUB_ERR_OUT_OF_MEMORY;

  /* Hash password */
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
  return plainmount_setkey (dev, derived_hash, cargs->key_size);
}


/* Read keyfile as a file */
static grub_err_t
plainmount_configure_keyfile (grub_cryptodisk_t dev, grub_plainmount_args_t cargs)
{
  grub_file_t keyfile = grub_file_open (cargs->keyfile, GRUB_FILE_TYPE_NONE);
  if (!keyfile)
      return grub_error (GRUB_ERR_FILE_NOT_FOUND, N_("cannot open keyfile %s"),
                       cargs->keyfile);

  if (grub_file_seek (keyfile, cargs->keyfile_offset) == (grub_off_t)-1)
      return grub_error (GRUB_ERR_FILE_READ_ERROR,
                        N_("cannot seek keyfile at offset %"PRIuGRUB_SIZE),
                        cargs->keyfile_offset);

  if (cargs->key_size > (keyfile->size - cargs->keyfile_offset))
      return grub_error (GRUB_ERR_BAD_ARGUMENT,
                         N_("Specified key size (%"PRIuGRUB_SIZE") is too small"
                            " for keyfile size (%"PRIuGRUB_SIZE") and offset (%"
                            PRIuGRUB_SIZE")"),
                         cargs->key_size, keyfile->size,
                         cargs->keyfile_offset);
  else
    cargs->key_size = keyfile->size - cargs->keyfile_offset;

  if (grub_file_read (keyfile, cargs->key_data, cargs->key_size) !=
       (grub_ssize_t) cargs->key_size)
     return grub_error (GRUB_ERR_FILE_READ_ERROR, N_("error reading key file"));

  return plainmount_setkey (dev, (grub_uint8_t*)cargs->key_data, cargs->key_size);
}


/* Read keyfile as a disk segment */
static grub_err_t
plainmount_configure_keydisk (grub_cryptodisk_t dev, grub_plainmount_args_t cargs)
{
  grub_err_t err;

  char *keydisk_name = grub_file_get_device_name (cargs->keyfile);
  grub_disk_t keydisk = grub_disk_open (cargs->keyfile);
  if (!keydisk)
    {
      err = grub_error (GRUB_ERR_BAD_ARGUMENT, N_("unable to open disk %s"),
                         keydisk_name);
      goto cleanup;
    }
  if (grub_disk_read (keydisk, 0, cargs->keyfile_offset,
                      cargs->key_size, cargs->key_data) != GRUB_ERR_NONE)
    {
      err = grub_error (GRUB_ERR_READ_ERROR, N_("failed to read from disk %s"),
                        keydisk_name);
      goto cleanup;
    }
  err = plainmount_setkey (dev, (grub_uint8_t*)cargs->key_data, cargs->key_size);

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
      err = grub_error (GRUB_ERR_BAD_ARGUMENT,
                        N_("cannot open disk %s"), diskname);
      goto exit;
    }

  /* Check whether required arguments are specified */
  if (!state[1].set || !state[4].set)
    {
      err = grub_error (GRUB_ERR_BAD_ARGUMENT, "cipher/key size must be set");
      goto exit;
    }
  if (!state[0].set && !state[7].set)
    {
      err = grub_error (GRUB_ERR_BAD_ARGUMENT, "hash algorithm must be set");
      goto exit;
    }

  /* Allocate all stuff here */
  cargs.hash =  state[0].set ? grub_strdup (state[0].arg) : NULL;
  cargs.cipher = grub_strdup (state[1].arg);
  cargs.keyfile = state[7].set ? grub_strdup (state[7].arg) : NULL;
  dev = grub_zalloc (sizeof *dev);
  cargs.key_data = grub_zalloc (GRUB_CRYPTODISK_MAX_PASSPHRASE);
  if ((!cargs.hash && state[0].set) || !cargs.cipher ||
      (!cargs.keyfile && state[7].set) || !dev || !cargs.key_data)
    {
      err = grub_error (GRUB_ERR_OUT_OF_MEMORY, "out of memory");
      goto exit;
    }

  /* Parse cmdline arguments */
  if (state[2].set)
    {
      cargs.offset = plainmount_parse_suffix (state[2].arg);
      if (cargs.offset == (grub_size_t)-1)
        {
          err = grub_error (GRUB_ERR_BAD_ARGUMENT,
	                    N_("unrecognized offset suffix"));
          goto exit;
        }
    }
  if (state[3].set)
  {
    cargs.size = grub_strtoull (state[3].arg, &p, 0);
    cargs.size = plainmount_parse_suffix (state[3].arg);
    if (cargs.size == (grub_size_t)-1)
      {
        err = grub_error (GRUB_ERR_BAD_ARGUMENT,
	                  N_("unrecognized disk size suffix"));
        goto exit;
      }
  }
  grub_errno = GRUB_ERR_NONE;
  cargs.key_size = grub_strtoull (state[4].arg, &p, 0) / 8;
  if (state[4].set && (*p != '\0' || grub_errno != GRUB_ERR_NONE))
   {
     err = grub_error (GRUB_ERR_BAD_ARGUMENT, N_("unrecognized key size"));
     goto exit;
   }
  cargs.sector_size = state[5].set ? grub_strtoull (state[5].arg, &p, 0) : 512;
  if (state[5].set && (*p != '\0' || grub_errno != GRUB_ERR_NONE))
   {
     err = grub_error (GRUB_ERR_BAD_ARGUMENT, N_("unrecognized sector size"));
     goto exit;
   }
  if (state[8].set)
  {
    cargs.keyfile_offset = plainmount_parse_suffix (state[8].arg);
    if (cargs.keyfile_offset == (grub_size_t)-1)
      {
        err = grub_error (GRUB_ERR_BAD_ARGUMENT,
	                  N_("unrecognized keyfile offset suffix"));
        goto exit;
      }
  }

  /* Check key size */
  if (cargs.key_size > GRUB_CRYPTODISK_MAX_KEYLEN)
    {
      err = grub_error (GRUB_ERR_BAD_ARGUMENT,
                        N_("invalid key size %"PRIuGRUB_SIZE
                           " (exceeds maximum %d bits)"),
                        cargs.key_size, GRUB_CRYPTODISK_MAX_KEYLEN * 8);
      goto exit;
    }

   /* Check password size */
   if (state[6].set && grub_strlen (state[6].arg) + 1 >
       GRUB_CRYPTODISK_MAX_PASSPHRASE)
     {
       err = grub_error (GRUB_ERR_BAD_ARGUMENT,
		         N_("password exceeds maximium size"));
       goto exit;
     }
   if (state[6].set)
    grub_strcpy (cargs.key_data, state[6].arg);

  /* Check cipher mode */
  cargs.mode = grub_strchr (cargs.cipher,'-');
  if (!cargs.mode)
    {
      err = grub_error (GRUB_ERR_BAD_ARGUMENT, N_("invalid cipher mode"));
      goto exit;
    }
  else
    *cargs.mode++ = '\0';

  /* Check cipher */
  if (grub_cryptodisk_setcipher (dev, cargs.cipher, cargs.mode)!= GRUB_ERR_NONE)
    {
      err = grub_error (GRUB_ERR_BAD_ARGUMENT,
		        N_("invalid cipher %s"), cargs.cipher);
      goto exit;
    }

  /* Warn if hash and keyfile are both provided */
  if (cargs.keyfile && state[0].arg)
    grub_printf_ (N_("warning: hash is ignored if keyfile is specified\n"));

  /* Warn if key file offset is provided without key file */
  if (!state[7].set && state[8].set)
    grub_printf_ (N_("warning: keyfile offset without keyfile is ignored\n"));

  /* Warn if -p option is specified with keyfile */
  if (state[6].set && state[7].set)
    grub_printf_ (N_("warning: password specified with -p option"
                     "is ignored if keyfile is provided\n"));

  grub_dprintf ("plainmount",
              "parameters: cipher=%s, hash=%s, key_size=%"PRIuGRUB_SIZE
	      ", keyfile=%s, keyfile offset=%"PRIuGRUB_SIZE"\n",
              cargs.cipher, cargs.hash, cargs.key_size,
              cargs.keyfile ? cargs.keyfile : NULL,
              cargs.keyfile_offset);

  err = plainmount_configure_sectors (dev, &cargs);
  if (err != GRUB_ERR_NONE)
    goto exit;

  /* Configure keyfile/keydisk/password */
  if (cargs.keyfile)
    if (grub_strchr (cargs.keyfile, '/'))
      err = plainmount_configure_keyfile (dev, &cargs);
    else
      err = plainmount_configure_keydisk (dev, &cargs);
  else
    err = plainmount_configure_password (dev, &cargs);
  if (err != GRUB_ERR_NONE)
    goto exit;

  err = grub_cryptodisk_insert (dev, diskname, cargs.disk);
  if (err != GRUB_ERR_NONE)
    {
      grub_printf_ (N_("cannot initialize cryptodisk. "
                    "Check cipher/key size/hash arguments.\n"));
      goto exit;
    }

  dev->modname = "plainmount";
  dev->source_disk = cargs.disk;
  plainmount_set_uuid (dev);

exit:
  grub_free (cargs.hash);
  grub_free (cargs.cipher);
  grub_free (cargs.keyfile);
  grub_free (cargs.key_data);
  if (err != GRUB_ERR_NONE && cargs.disk)
    grub_disk_close (cargs.disk);
  if (err != GRUB_ERR_NONE && dev)
    grub_free (dev);
  return err;
}

static grub_extcmd_t cmd;
GRUB_MOD_INIT (plainmount)
{
  cmd = grub_register_extcmd ("plainmount", grub_cmd_plainmount, 0,
			      N_("[-h hash] [-c cipher] [-o offset] [-b disk-size]"
			      " [-s key-size] [-S sector-size] [-p password] "
			      "[[-d keyfile] [-O keyfile offset]] <SOURCE>"),
			      N_("Open partition encrypted in plain mode."),
			      options);
}

GRUB_MOD_FINI (plainmount)
{
  grub_unregister_extcmd (cmd);
}
