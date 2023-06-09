#include<stdio.h>
int main(){
   int mac = 123;
   int key = 789;

   int enc = mac^key;
   printf("encrypted text=%d\n",enc);

   int plain = enc^key;
   printf("decrypted text = %d\n",plain);

   return 0;
}