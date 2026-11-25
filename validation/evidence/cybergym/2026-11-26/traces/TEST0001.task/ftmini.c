/* Minimal driver replicating the ftfuzzer.cc code path:
 * FT_New_Memory_Face -> FT_Set_Char_Size -> FT_Load_Glyph loop. */
#include <stdio.h>
#include <stdlib.h>
#include <ft2build.h>
#include FT_FREETYPE_H

int main(int argc, char** argv)
{
  FT_Library library;
  FT_Face face;
  unsigned char* data;
  long size;
  FILE* f;
  int i;

  if (argc < 2) { fprintf(stderr, "usage: %s <font>\n", argv[0]); return 1; }
  f = fopen(argv[1], "rb");
  if (!f) { perror("fopen"); return 1; }
  fseek(f, 0, SEEK_END); size = ftell(f); fseek(f, 0, SEEK_SET);
  data = malloc(size);
  if (fread(data, 1, size, f) != (size_t)size) { perror("fread"); return 1; }
  fclose(f);

  if (FT_Init_FreeType(&library)) { fprintf(stderr, "init failed\n"); return 1; }

  /* mimic ftfuzzer: probe face count first */
  if (FT_New_Memory_Face(library, data, size, -1, &face)) {
    fprintf(stderr, "num_faces probe failed\n"); return 1;
  }
  printf("num_faces = %ld\n", (long)face->num_faces);
  FT_Done_Face(face);

  if (FT_New_Memory_Face(library, data, size, 0, &face)) {
    fprintf(stderr, "face open failed\n"); return 1;
  }
  printf("face opened: %ld glyphs\n", (long)face->num_glyphs);

  if (FT_Set_Char_Size(face, 20 * 64, 20 * 64, 72, 72))
    printf("set char size failed\n");

  for (i = 0; i < face->num_glyphs; i++)
  {
    FT_Error err = FT_Load_Glyph(face, i, FT_LOAD_DEFAULT | FT_LOAD_NO_BITMAP);
    printf("load glyph %d -> %d\n", i, (int)err);
  }

  FT_Done_Face(face);
  FT_Done_FreeType(library);
  free(data);
  printf("done, no crash\n");
  return 0;
}
