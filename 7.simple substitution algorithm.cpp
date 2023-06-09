#include <stdio.h>
#include <string.h>

int main()
{
   char cipherText[] = ("53‡‡†305))6*;4826)4‡.)4‡);806*;48†8¶60))85;;]8*;:‡*8†83(88)5*†;46(;88*96*?;8)*‡(;485);5*†2:*‡(;4956*2(5*—4)8¶8*;4069285);)6†8)4‡‡;1(‡9;48081;8:8‡1;48†85;4)485†528806*81 (‡9;48;(88;4(‡?34;48)4‡;161;:188;‡?;;";
   int length = strlen(cipherText);
   char plainText[length + 1];
   int i;
   for (i = 0; i < length; i++)
   {
      char currentChar = cipherText[i];
      switch (currentChar)
      {
         case '1':
            plainText[i] = '.';
            break;
         case '2':
            plainText[i] = 'b';
            break;
         case '3':
            plainText[i] = 'c';
            break;
         case '4':
            plainText[i] = 'd';
            break;
         case '5':
            plainText[i] = 'e';
            break;
         case '6':
            plainText[i] = 'f';
            break;
         case '7':
            plainText[i] = 'g';
            break;
         case '8':
            plainText[i] = 'h';
            break;
         case '9':
            plainText[i] = 'i';
            break;
         case '0':
            plainText[i] = 'j';
            break;
         case ';':
            plainText[i] = 'k';
            break;
         case ':':
            plainText[i] = 'l';
            break;
         case '(':
            plainText[i] = 'm';
            break;
         case ')':
            plainText[i] = 'n';
            break;
         case '?':
            plainText[i] = 'o';
            break;
         case '—':
            plainText[i] = 'p';
            break;
         case '†':
            plainText[i] = 'q';
            break;
         case '‡':
            plainText[i] = 'O';
            break;
         case '¶':
            plainText[i] = 's';
            break;
         case '*':
            plainText[i] = 't';
            break;
         case ']':
            plainText[i] = 'u';
            break;
         case '[':
            plainText[i] = 'v';
            break;
      }
   }
   plainText[length] = '\0';
   printf("The plain text is: %s", plainText);
   return 0;
}