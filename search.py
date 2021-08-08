from idaapi import *
danger_funcs = ['getchar', 'scanf', 'gets', 'getc', 'fread', 'fscanf', 'fgets', 'fgetc', 'strcpy', 'sprintf', 'strncpy', 'memcpy', 'memmove', 'strcat', 'memset', 'malloc', 'calloc', 'realloc', 'free']
for func in danger_funcs:
 addr = LocByName(func)
 if addr != BADADDR:
  cross_refs = CodeRefsTo (addr, 0)
  print('-----')
  print ('cross referenes to %s' % func)
  for ref in cross_refs:
   first_refs = CodeRefsFrom(ref, 0)
   print('%08x' % ref)
   #SetColor( ref, CUC_ITEM, 0x0000FF)
   for ref1 in first_refs:
    print('%08x' % ref1)