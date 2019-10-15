int __cdecl main(int argc, const char **argv, const char **envp)
{
  int v4; // [esp+0h] [ebp-18h]
  int v5; // [esp+4h] [ebp-14h]
  unsigned int seed; // [esp+8h] [ebp-10h]
  int i; // [esp+Ch] [ebp-Ch]
  int *v8; // [esp+10h] [ebp-8h]

  v8 = &argc;
  puts((const char *)&unk_A40);
  puts((const char *)&unk_A40);
  puts("                                                                             ");
  puts("                          #                mmmmm  mmmmm    \"    mm   m   mmm ");
  puts("  mmm    mmm    mmm    mmm#          mmm   #   \"# #   \"# mmm    #\"m  # m\"   \"");
  puts(" #   \"  #\"  #  #\"  #  #\" \"#         #   \"  #mmm#\" #mmmm\"   #    # #m # #   mm");
  puts("  \"\"\"m  #\"\"\"\"  #\"\"\"\"  #   #          \"\"\"m  #      #   \"m   #    #  # # #    #");
  puts(" \"mmm\"  \"#mm\"  \"#mm\"  \"#m##         \"mmm\"  #      #    \" mm#mm  #   ##  \"mmm\"");
  puts("                                                                             ");
  puts((const char *)&unk_A40);
  puts((const char *)&unk_A40);
  puts("Welcome! The game is easy: you jump on a sPRiNG.");
  puts("How high will you fly?");
  puts((const char *)&unk_A40);
  fflush(stdout);
  seed = time(0);
  srand(seed);
  for ( i = 1; i <= 30; ++i )
  {
    printf("LEVEL (%d/30)\n", i);
    puts((const char *)&unk_A40);
    LOBYTE(v5) = rand() & 0xF;
    v5 = (unsigned __int8)v5;
    printf("Guess the height: ");
    fflush(stdout);
    __isoc99_scanf("%d", &v4);
    fflush(stdin);
    if ( v5 != v4 )
    {
      puts("WRONG! Sorry, better luck next time!");
      fflush(stdout);
      exit(-1);
    }
  }
  puts("Congratulation! You've won! Here is your flag:\n");
  get_flag();
  fflush(stdout);
  return 0;
}