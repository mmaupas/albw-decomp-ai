/* 0x17E274: twin of 002CC7B4 with callee 0060EE28. */
typedef unsigned int u32;
extern void func_0060EE28(void);
void target(unsigned a0)
{
  unsigned h901, h902, h903, t2;
  func_0060EE28();
  t2 = a0 + 0x800;
  h901 = a0 + 0x998;
  h902 = *(unsigned *)((char *)a0 + 0x3D0);
  *(unsigned *)((char *)h901) = h902;
  *(unsigned *)((char *)a0 + 0x99C) = *(unsigned *)((char *)a0 + 0x3D4);
  h903 = a0 + 0x3D8;
  *(unsigned *)((char *)a0 + 0x9A0) = *(unsigned *)((char *)h903);
  *(float *)((char *)t2 + 0x19C) = (*(float *)((char *)t2 + 0x19C)) + (*(float *)((char *)t2 + 0x38));
  *(unsigned short *)((char *)a0 + 0x9AE) = 0;
  return;
}
