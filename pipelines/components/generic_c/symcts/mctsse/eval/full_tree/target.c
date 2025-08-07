
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int main(int argc, char* argv[]) {
    unsigned char buf[0x1000];
    memset(buf, 0, 0x1000);
    int num_chars = read(0, buf, 0x1000);

 if (buf[0] < 148) {
  puts("left");
  if (buf[1] < 65) {
   puts("left");
   if (buf[2] < 104) {
    puts("left");
    if (buf[3] < 67) {
     puts("left");
     if (buf[4] < 176) {
      puts("left");
      if (buf[5] < 91) {
       puts("left");
       if (buf[6] < 51) {
        puts("left");
        if (buf[7] < 203) {
         puts("left");
         if (buf[8] < 176) {
          puts("left");
          if (buf[9] < 117) {
           puts("left");
          } else {
           puts("right");
          }
         } else {
          puts("right");
          if (buf[9] < 27) {
           puts("left");
          } else {
           puts("right");
          }
         }
        } else {
         puts("right");
         if (buf[8] < 118) {
          puts("left");
          if (buf[9] < 254) {
           puts("left");
          } else {
           puts("right");
          }
         } else {
          puts("right");
          if (buf[9] < 30) {
           puts("left");
          } else {
           puts("right");
          }
         }
        }
       } else {
        puts("right");
        if (buf[7] < 234) {
         puts("left");
         if (buf[8] < 206) {
          puts("left");
          if (buf[9] < 105) {
           puts("left");
          } else {
           puts("right");
          }
         } else {
          puts("right");
          if (buf[9] < 180) {
           puts("left");
          } else {
           puts("right");
          }
         }
        } else {
         puts("right");
         if (buf[8] < 14) {
          puts("left");
          if (buf[9] < 75) {
           puts("left");
          } else {
           puts("right");
          }
         } else {
          puts("right");
          if (buf[9] < 105) {
           puts("left");
          } else {
           puts("right");
          }
         }
        }
       }
      } else {
       puts("right");
       if (buf[6] < 199) {
        puts("left");
        if (buf[7] < 107) {
         puts("left");
         if (buf[8] < 44) {
          puts("left");
          if (buf[9] < 55) {
           puts("left");
          } else {
           puts("right");
          }
         } else {
          puts("right");
          if (buf[9] < 55) {
           puts("left");
          } else {
           puts("right");
          }
         }
        } else {
         puts("right");
         if (buf[8] < 248) {
          puts("left");
          if (buf[9] < 81) {
           puts("left");
          } else {
           puts("right");
          }
         } else {
          puts("right");
          if (buf[9] < 206) {
           puts("left");
          } else {
           puts("right");
          }
         }
        }
       } else {
        puts("right");
        if (buf[7] < 28) {
         puts("left");
         if (buf[8] < 141) {
          puts("left");
          if (buf[9] < 169) {
           puts("left");
          } else {
           puts("right");
          }
         } else {
          puts("right");
          if (buf[9] < 207) {
           puts("left");
          } else {
           puts("right");
          }
         }
        } else {
         puts("right");
         if (buf[8] < 249) {
          puts("left");
          if (buf[9] < 40) {
           puts("left");
          } else {
           puts("right");
          }
         } else {
          puts("right");
          if (buf[9] < 156) {
           puts("left");
          } else {
           puts("right");
          }
         }
        }
       }
      }
     } else {
      puts("right");
      if (buf[5] < 89) {
       puts("left");
       if (buf[6] < 159) {
        puts("left");
        if (buf[7] < 156) {
         puts("left");
         if (buf[8] < 115) {
          puts("left");
          if (buf[9] < 255) {
           puts("left");
          } else {
           puts("right");
          }
         } else {
          puts("right");
          if (buf[9] < 4) {
           puts("left");
          } else {
           puts("right");
          }
         }
        } else {
         puts("right");
         if (buf[8] < 6) {
          puts("left");
          if (buf[9] < 159) {
           puts("left");
          } else {
           puts("right");
          }
         } else {
          puts("right");
          if (buf[9] < 22) {
           puts("left");
          } else {
           puts("right");
          }
         }
        }
       } else {
        puts("right");
        if (buf[7] < 195) {
         puts("left");
         if (buf[8] < 95) {
          puts("left");
          if (buf[9] < 138) {
           puts("left");
          } else {
           puts("right");
          }
         } else {
          puts("right");
          if (buf[9] < 143) {
           puts("left");
          } else {
           puts("right");
          }
         }
        } else {
         puts("right");
         if (buf[8] < 61) {
          puts("left");
          if (buf[9] < 230) {
           puts("left");
          } else {
           puts("right");
          }
         } else {
          puts("right");
          if (buf[9] < 198) {
           puts("left");
          } else {
           puts("right");
          }
         }
        }
       }
      } else {
       puts("right");
       if (buf[6] < 192) {
        puts("left");
        if (buf[7] < 149) {
         puts("left");
         if (buf[8] < 198) {
          puts("left");
          if (buf[9] < 149) {
           puts("left");
          } else {
           puts("right");
          }
         } else {
          puts("right");
          if (buf[9] < 234) {
           puts("left");
          } else {
           puts("right");
          }
         }
        } else {
         puts("right");
         if (buf[8] < 219) {
          puts("left");
          if (buf[9] < 229) {
           puts("left");
          } else {
           puts("right");
          }
         } else {
          puts("right");
          if (buf[9] < 187) {
           puts("left");
          } else {
           puts("right");
          }
         }
        }
       } else {
        puts("right");
        if (buf[7] < 135) {
         puts("left");
         if (buf[8] < 132) {
          puts("left");
          if (buf[9] < 45) {
           puts("left");
          } else {
           puts("right");
          }
         } else {
          puts("right");
          if (buf[9] < 60) {
           puts("left");
          } else {
           puts("right");
          }
         }
        } else {
         puts("right");
         if (buf[8] < 220) {
          puts("left");
          if (buf[9] < 32) {
           puts("left");
          } else {
           puts("right");
          }
         } else {
          puts("right");
          if (buf[9] < 89) {
           puts("left");
          } else {
           puts("right");
          }
         }
        }
       }
      }
     }
    } else {
     puts("right");
     if (buf[4] < 211) {
      puts("left");
      if (buf[5] < 29) {
       puts("left");
       if (buf[6] < 41) {
        puts("left");
        if (buf[7] < 196) {
         puts("left");
         if (buf[8] < 135) {
          puts("left");
          if (buf[9] < 17) {
           puts("left");
          } else {
           puts("right");
          }
         } else {
          puts("right");
          if (buf[9] < 118) {
           puts("left");
          } else {
           puts("right");
          }
         }
        } else {
         puts("right");
         if (buf[8] < 27) {
          puts("left");
          if (buf[9] < 242) {
           puts("left");
          } else {
           puts("right");
          }
         } else {
          puts("right");
          if (buf[9] < 170) {
           puts("left");
          } else {
           puts("right");
          }
         }
        }
       } else {
        puts("right");
        if (buf[7] < 50) {
         puts("left");
         if (buf[8] < 14) {
          puts("left");
          if (buf[9] < 15) {
           puts("left");
          } else {
           puts("right");
          }
         } else {
          puts("right");
          if (buf[9] < 151) {
           puts("left");
          } else {
           puts("right");
          }
         }
        } else {
         puts("right");
         if (buf[8] < 70) {
          puts("left");
          if (buf[9] < 89) {
           puts("left");
          } else {
           puts("right");
          }
         } else {
          puts("right");
          if (buf[9] < 81) {
           puts("left");
          } else {
           puts("right");
          }
         }
        }
       }
      } else {
       puts("right");
       if (buf[6] < 96) {
        puts("left");
        if (buf[7] < 244) {
         puts("left");
         if (buf[8] < 25) {
          puts("left");
          if (buf[9] < 145) {
           puts("left");
          } else {
           puts("right");
          }
         } else {
          puts("right");
          if (buf[9] < 144) {
           puts("left");
          } else {
           puts("right");
          }
         }
        } else {
         puts("right");
         if (buf[8] < 236) {
          puts("left");
          if (buf[9] < 79) {
           puts("left");
          } else {
           puts("right");
          }
         } else {
          puts("right");
          if (buf[9] < 210) {
           puts("left");
          } else {
           puts("right");
          }
         }
        }
       } else {
        puts("right");
        if (buf[7] < 110) {
         puts("left");
         if (buf[8] < 79) {
          puts("left");
          if (buf[9] < 55) {
           puts("left");
          } else {
           puts("right");
          }
         } else {
          puts("right");
          if (buf[9] < 100) {
           puts("left");
          } else {
           puts("right");
          }
         }
        } else {
         puts("right");
         if (buf[8] < 80) {
          puts("left");
          if (buf[9] < 78) {
           puts("left");
          } else {
           puts("right");
          }
         } else {
          puts("right");
          if (buf[9] < 152) {
           puts("left");
          } else {
           puts("right");
          }
         }
        }
       }
      }
     } else {
      puts("right");
      if (buf[5] < 181) {
       puts("left");
       if (buf[6] < 250) {
        puts("left");
        if (buf[7] < 172) {
         puts("left");
         if (buf[8] < 193) {
          puts("left");
          if (buf[9] < 214) {
           puts("left");
          } else {
           puts("right");
          }
         } else {
          puts("right");
          if (buf[9] < 158) {
           puts("left");
          } else {
           puts("right");
          }
         }
        } else {
         puts("right");
         if (buf[8] < 81) {
          puts("left");
          if (buf[9] < 162) {
           puts("left");
          } else {
           puts("right");
          }
         } else {
          puts("right");
          if (buf[9] < 205) {
           puts("left");
          } else {
           puts("right");
          }
         }
        }
       } else {
        puts("right");
        if (buf[7] < 123) {
         puts("left");
         if (buf[8] < 48) {
          puts("left");
          if (buf[9] < 215) {
           puts("left");
          } else {
           puts("right");
          }
         } else {
          puts("right");
          if (buf[9] < 227) {
           puts("left");
          } else {
           puts("right");
          }
         }
        } else {
         puts("right");
         if (buf[8] < 137) {
          puts("left");
          if (buf[9] < 243) {
           puts("left");
          } else {
           puts("right");
          }
         } else {
          puts("right");
          if (buf[9] < 51) {
           puts("left");
          } else {
           puts("right");
          }
         }
        }
       }
      } else {
       puts("right");
       if (buf[6] < 157) {
        puts("left");
        if (buf[7] < 184) {
         puts("left");
         if (buf[8] < 168) {
          puts("left");
          if (buf[9] < 112) {
           puts("left");
          } else {
           puts("right");
          }
         } else {
          puts("right");
          if (buf[9] < 174) {
           puts("left");
          } else {
           puts("right");
          }
         }
        } else {
         puts("right");
         if (buf[8] < 164) {
          puts("left");
          if (buf[9] < 76) {
           puts("left");
          } else {
           puts("right");
          }
         } else {
          puts("right");
          if (buf[9] < 151) {
           puts("left");
          } else {
           puts("right");
          }
         }
        }
       } else {
        puts("right");
        if (buf[7] < 12) {
         puts("left");
         if (buf[8] < 165) {
          puts("left");
          if (buf[9] < 86) {
           puts("left");
          } else {
           puts("right");
          }
         } else {
          puts("right");
          if (buf[9] < 87) {
           puts("left");
          } else {
           puts("right");
          }
         }
        } else {
         puts("right");
         if (buf[8] < 130) {
          puts("left");
          if (buf[9] < 237) {
           puts("left");
          } else {
           puts("right");
          }
         } else {
          puts("right");
          if (buf[9] < 71) {
           puts("left");
          } else {
           puts("right");
          }
         }
        }
       }
      }
     }
    }
   } else {
    puts("right");
    if (buf[3] < 77) {
     puts("left");
     if (buf[4] < 124) {
      puts("left");
      if (buf[5] < 10) {
       puts("left");
       if (buf[6] < 130) {
        puts("left");
        if (buf[7] < 109) {
         puts("left");
         if (buf[8] < 88) {
          puts("left");
          if (buf[9] < 79) {
           puts("left");
          } else {
           puts("right");
          }
         } else {
          puts("right");
          if (buf[9] < 55) {
           puts("left");
          } else {
           puts("right");
          }
         }
        } else {
         puts("right");
         if (buf[8] < 90) {
          puts("left");
          if (buf[9] < 178) {
           puts("left");
          } else {
           puts("right");
          }
         } else {
          puts("right");
          if (buf[9] < 253) {
           puts("left");
          } else {
           puts("right");
          }
         }
        }
       } else {
        puts("right");
        if (buf[7] < 9) {
         puts("left");
         if (buf[8] < 23) {
          puts("left");
          if (buf[9] < 113) {
           puts("left");
          } else {
           puts("right");
          }
         } else {
          puts("right");
          if (buf[9] < 209) {
           puts("left");
          } else {
           puts("right");
          }
         }
        } else {
         puts("right");
         if (buf[8] < 4) {
          puts("left");
          if (buf[9] < 14) {
           puts("left");
          } else {
           puts("right");
          }
         } else {
          puts("right");
          if (buf[9] < 131) {
           puts("left");
          } else {
           puts("right");
          }
         }
        }
       }
      } else {
       puts("right");
       if (buf[6] < 100) {
        puts("left");
        if (buf[7] < 155) {
         puts("left");
         if (buf[8] < 8) {
          puts("left");
          if (buf[9] < 237) {
           puts("left");
          } else {
           puts("right");
          }
         } else {
          puts("right");
          if (buf[9] < 140) {
           puts("left");
          } else {
           puts("right");
          }
         }
        } else {
         puts("right");
         if (buf[8] < 162) {
          puts("left");
          if (buf[9] < 238) {
           puts("left");
          } else {
           puts("right");
          }
         } else {
          puts("right");
          if (buf[9] < 4) {
           puts("left");
          } else {
           puts("right");
          }
         }
        }
       } else {
        puts("right");
        if (buf[7] < 254) {
         puts("left");
         if (buf[8] < 21) {
          puts("left");
          if (buf[9] < 67) {
           puts("left");
          } else {
           puts("right");
          }
         } else {
          puts("right");
          if (buf[9] < 174) {
           puts("left");
          } else {
           puts("right");
          }
         }
        } else {
         puts("right");
         if (buf[8] < 232) {
          puts("left");
          if (buf[9] < 246) {
           puts("left");
          } else {
           puts("right");
          }
         } else {
          puts("right");
          if (buf[9] < 178) {
           puts("left");
          } else {
           puts("right");
          }
         }
        }
       }
      }
     } else {
      puts("right");
      if (buf[5] < 249) {
       puts("left");
       if (buf[6] < 248) {
        puts("left");
        if (buf[7] < 57) {
         puts("left");
         if (buf[8] < 52) {
          puts("left");
          if (buf[9] < 201) {
           puts("left");
          } else {
           puts("right");
          }
         } else {
          puts("right");
          if (buf[9] < 67) {
           puts("left");
          } else {
           puts("right");
          }
         }
        } else {
         puts("right");
         if (buf[8] < 230) {
          puts("left");
          if (buf[9] < 143) {
           puts("left");
          } else {
           puts("right");
          }
         } else {
          puts("right");
          if (buf[9] < 130) {
           puts("left");
          } else {
           puts("right");
          }
         }
        }
       } else {
        puts("right");
        if (buf[7] < 15) {
         puts("left");
         if (buf[8] < 206) {
          puts("left");
          if (buf[9] < 234) {
           puts("left");
          } else {
           puts("right");
          }
         } else {
          puts("right");
          if (buf[9] < 179) {
           puts("left");
          } else {
           puts("right");
          }
         }
        } else {
         puts("right");
         if (buf[8] < 198) {
          puts("left");
          if (buf[9] < 27) {
           puts("left");
          } else {
           puts("right");
          }
         } else {
          puts("right");
          if (buf[9] < 147) {
           puts("left");
          } else {
           puts("right");
          }
         }
        }
       }
      } else {
       puts("right");
       if (buf[6] < 149) {
        puts("left");
        if (buf[7] < 107) {
         puts("left");
         if (buf[8] < 122) {
          puts("left");
          if (buf[9] < 104) {
           puts("left");
          } else {
           puts("right");
          }
         } else {
          puts("right");
          if (buf[9] < 247) {
           puts("left");
          } else {
           puts("right");
          }
         }
        } else {
         puts("right");
         if (buf[8] < 97) {
          puts("left");
          if (buf[9] < 199) {
           puts("left");
          } else {
           puts("right");
          }
         } else {
          puts("right");
          if (buf[9] < 94) {
           puts("left");
          } else {
           puts("right");
          }
         }
        }
       } else {
        puts("right");
        if (buf[7] < 104) {
         puts("left");
         if (buf[8] < 18) {
          puts("left");
          if (buf[9] < 9) {
           puts("left");
          } else {
           puts("right");
          }
         } else {
          puts("right");
          if (buf[9] < 224) {
           puts("left");
          } else {
           puts("right");
          }
         }
        } else {
         puts("right");
         if (buf[8] < 208) {
          puts("left");
          if (buf[9] < 95) {
           puts("left");
          } else {
           puts("right");
          }
         } else {
          puts("right");
          if (buf[9] < 90) {
           puts("left");
          } else {
           puts("right");
          }
         }
        }
       }
      }
     }
    } else {
     puts("right");
     if (buf[4] < 144) {
      puts("left");
      if (buf[5] < 11) {
       puts("left");
       if (buf[6] < 38) {
        puts("left");
        if (buf[7] < 237) {
         puts("left");
         if (buf[8] < 76) {
          puts("left");
          if (buf[9] < 174) {
           puts("left");
          } else {
           puts("right");
          }
         } else {
          puts("right");
          if (buf[9] < 157) {
           puts("left");
          } else {
           puts("right");
          }
         }
        } else {
         puts("right");
         if (buf[8] < 143) {
          puts("left");
          if (buf[9] < 142) {
           puts("left");
          } else {
           puts("right");
          }
         } else {
          puts("right");
          if (buf[9] < 245) {
           puts("left");
          } else {
           puts("right");
          }
         }
        }
       } else {
        puts("right");
        if (buf[7] < 218) {
         puts("left");
         if (buf[8] < 46) {
          puts("left");
          if (buf[9] < 130) {
           puts("left");
          } else {
           puts("right");
          }
         } else {
          puts("right");
          if (buf[9] < 230) {
           puts("left");
          } else {
           puts("right");
          }
         }
        } else {
         puts("right");
         if (buf[8] < 141) {
          puts("left");
          if (buf[9] < 237) {
           puts("left");
          } else {
           puts("right");
          }
         } else {
          puts("right");
          if (buf[9] < 189) {
           puts("left");
          } else {
           puts("right");
          }
         }
        }
       }
      } else {
       puts("right");
       if (buf[6] < 73) {
        puts("left");
        if (buf[7] < 211) {
         puts("left");
         if (buf[8] < 83) {
          puts("left");
          if (buf[9] < 120) {
           puts("left");
          } else {
           puts("right");
          }
         } else {
          puts("right");
          if (buf[9] < 160) {
           puts("left");
          } else {
           puts("right");
          }
         }
        } else {
         puts("right");
         if (buf[8] < 119) {
          puts("left");
          if (buf[9] < 205) {
           puts("left");
          } else {
           puts("right");
          }
         } else {
          puts("right");
          if (buf[9] < 211) {
           puts("left");
          } else {
           puts("right");
          }
         }
        }
       } else {
        puts("right");
        if (buf[7] < 89) {
         puts("left");
         if (buf[8] < 24) {
          puts("left");
          if (buf[9] < 252) {
           puts("left");
          } else {
           puts("right");
          }
         } else {
          puts("right");
          if (buf[9] < 239) {
           puts("left");
          } else {
           puts("right");
          }
         }
        } else {
         puts("right");
         if (buf[8] < 198) {
          puts("left");
          if (buf[9] < 140) {
           puts("left");
          } else {
           puts("right");
          }
         } else {
          puts("right");
          if (buf[9] < 91) {
           puts("left");
          } else {
           puts("right");
          }
         }
        }
       }
      }
     } else {
      puts("right");
      if (buf[5] < 117) {
       puts("left");
       if (buf[6] < 161) {
        puts("left");
        if (buf[7] < 178) {
         puts("left");
         if (buf[8] < 245) {
          puts("left");
          if (buf[9] < 142) {
           puts("left");
          } else {
           puts("right");
          }
         } else {
          puts("right");
          if (buf[9] < 236) {
           puts("left");
          } else {
           puts("right");
          }
         }
        } else {
         puts("right");
         if (buf[8] < 253) {
          puts("left");
          if (buf[9] < 58) {
           puts("left");
          } else {
           puts("right");
          }
         } else {
          puts("right");
          if (buf[9] < 98) {
           puts("left");
          } else {
           puts("right");
          }
         }
        }
       } else {
        puts("right");
        if (buf[7] < 164) {
         puts("left");
         if (buf[8] < 211) {
          puts("left");
          if (buf[9] < 247) {
           puts("left");
          } else {
           puts("right");
          }
         } else {
          puts("right");
          if (buf[9] < 49) {
           puts("left");
          } else {
           puts("right");
          }
         }
        } else {
         puts("right");
         if (buf[8] < 3) {
          puts("left");
          if (buf[9] < 50) {
           puts("left");
          } else {
           puts("right");
          }
         } else {
          puts("right");
          if (buf[9] < 28) {
           puts("left");
          } else {
           puts("right");
          }
         }
        }
       }
      } else {
       puts("right");
       if (buf[6] < 91) {
        puts("left");
        if (buf[7] < 108) {
         puts("left");
         if (buf[8] < 28) {
          puts("left");
          if (buf[9] < 12) {
           puts("left");
          } else {
           puts("right");
          }
         } else {
          puts("right");
          if (buf[9] < 110) {
           puts("left");
          } else {
           puts("right");
          }
         }
        } else {
         puts("right");
         if (buf[8] < 225) {
          puts("left");
          if (buf[9] < 212) {
           puts("left");
          } else {
           puts("right");
          }
         } else {
          puts("right");
          if (buf[9] < 71) {
           puts("left");
          } else {
           puts("right");
          }
         }
        }
       } else {
        puts("right");
        if (buf[7] < 78) {
         puts("left");
         if (buf[8] < 207) {
          puts("left");
          if (buf[9] < 74) {
           puts("left");
          } else {
           puts("right");
          }
         } else {
          puts("right");
          if (buf[9] < 116) {
           puts("left");
          } else {
           puts("right");
          }
         }
        } else {
         puts("right");
         if (buf[8] < 125) {
          puts("left");
          if (buf[9] < 22) {
           puts("left");
          } else {
           puts("right");
          }
         } else {
          puts("right");
          if (buf[9] < 86) {
           puts("left");
          } else {
           puts("right");
          }
         }
        }
       }
      }
     }
    }
   }
  } else {
   puts("right");
   if (buf[2] < 78) {
    puts("left");
    if (buf[3] < 165) {
     puts("left");
     if (buf[4] < 107) {
      puts("left");
      if (buf[5] < 43) {
       puts("left");
       if (buf[6] < 196) {
        puts("left");
        if (buf[7] < 245) {
         puts("left");
         if (buf[8] < 148) {
          puts("left");
          if (buf[9] < 240) {
           puts("left");
          } else {
           puts("right");
          }
         } else {
          puts("right");
          if (buf[9] < 110) {
           puts("left");
          } else {
           puts("right");
          }
         }
        } else {
         puts("right");
         if (buf[8] < 213) {
          puts("left");
          if (buf[9] < 34) {
           puts("left");
          } else {
           puts("right");
          }
         } else {
          puts("right");
          if (buf[9] < 231) {
           puts("left");
          } else {
           puts("right");
          }
         }
        }
       } else {
        puts("right");
        if (buf[7] < 244) {
         puts("left");
         if (buf[8] < 183) {
          puts("left");
          if (buf[9] < 130) {
           puts("left");
          } else {
           puts("right");
          }
         } else {
          puts("right");
          if (buf[9] < 111) {
           puts("left");
          } else {
           puts("right");
          }
         }
        } else {
         puts("right");
         if (buf[8] < 240) {
          puts("left");
          if (buf[9] < 224) {
           puts("left");
          } else {
           puts("right");
          }
         } else {
          puts("right");
          if (buf[9] < 4) {
           puts("left");
          } else {
           puts("right");
          }
         }
        }
       }
      } else {
       puts("right");
       if (buf[6] < 143) {
        puts("left");
        if (buf[7] < 48) {
         puts("left");
         if (buf[8] < 66) {
          puts("left");
          if (buf[9] < 210) {
           puts("left");
          } else {
           puts("right");
          }
         } else {
          puts("right");
          if (buf[9] < 254) {
           puts("left");
          } else {
           puts("right");
          }
         }
        } else {
         puts("right");
         if (buf[8] < 100) {
          puts("left");
          if (buf[9] < 214) {
           puts("left");
          } else {
           puts("right");
          }
         } else {
          puts("right");
          if (buf[9] < 184) {
           puts("left");
          } else {
           puts("right");
          }
         }
        }
       } else {
        puts("right");
        if (buf[7] < 122) {
         puts("left");
         if (buf[8] < 245) {
          puts("left");
          if (buf[9] < 14) {
           puts("left");
          } else {
           puts("right");
          }
         } else {
          puts("right");
          if (buf[9] < 36) {
           puts("left");
          } else {
           puts("right");
          }
         }
        } else {
         puts("right");
         if (buf[8] < 138) {
          puts("left");
          if (buf[9] < 238) {
           puts("left");
          } else {
           puts("right");
          }
         } else {
          puts("right");
          if (buf[9] < 178) {
           puts("left");
          } else {
           puts("right");
          }
         }
        }
       }
      }
     } else {
      puts("right");
      if (buf[5] < 60) {
       puts("left");
       if (buf[6] < 238) {
        puts("left");
        if (buf[7] < 109) {
         puts("left");
         if (buf[8] < 94) {
          puts("left");
          if (buf[9] < 208) {
           puts("left");
          } else {
           puts("right");
          }
         } else {
          puts("right");
          if (buf[9] < 1) {
           puts("left");
          } else {
           puts("right");
          }
         }
        } else {
         puts("right");
         if (buf[8] < 217) {
          puts("left");
          if (buf[9] < 251) {
           puts("left");
          } else {
           puts("right");
          }
         } else {
          puts("right");
          if (buf[9] < 244) {
           puts("left");
          } else {
           puts("right");
          }
         }
        }
       } else {
        puts("right");
        if (buf[7] < 134) {
         puts("left");
         if (buf[8] < 204) {
          puts("left");
          if (buf[9] < 218) {
           puts("left");
          } else {
           puts("right");
          }
         } else {
          puts("right");
          if (buf[9] < 168) {
           puts("left");
          } else {
           puts("right");
          }
         }
        } else {
         puts("right");
         if (buf[8] < 136) {
          puts("left");
          if (buf[9] < 246) {
           puts("left");
          } else {
           puts("right");
          }
         } else {
          puts("right");
          if (buf[9] < 34) {
           puts("left");
          } else {
           puts("right");
          }
         }
        }
       }
      } else {
       puts("right");
       if (buf[6] < 183) {
        puts("left");
        if (buf[7] < 99) {
         puts("left");
         if (buf[8] < 232) {
          puts("left");
          if (buf[9] < 255) {
           puts("left");
          } else {
           puts("right");
          }
         } else {
          puts("right");
          if (buf[9] < 199) {
           puts("left");
          } else {
           puts("right");
          }
         }
        } else {
         puts("right");
         if (buf[8] < 97) {
          puts("left");
          if (buf[9] < 21) {
           puts("left");
          } else {
           puts("right");
          }
         } else {
          puts("right");
          if (buf[9] < 37) {
           puts("left");
          } else {
           puts("right");
          }
         }
        }
       } else {
        puts("right");
        if (buf[7] < 246) {
         puts("left");
         if (buf[8] < 152) {
          puts("left");
          if (buf[9] < 182) {
           puts("left");
          } else {
           puts("right");
          }
         } else {
          puts("right");
          if (buf[9] < 27) {
           puts("left");
          } else {
           puts("right");
          }
         }
        } else {
         puts("right");
         if (buf[8] < 105) {
          puts("left");
          if (buf[9] < 232) {
           puts("left");
          } else {
           puts("right");
          }
         } else {
          puts("right");
          if (buf[9] < 134) {
           puts("left");
          } else {
           puts("right");
          }
         }
        }
       }
      }
     }
    } else {
     puts("right");
     if (buf[4] < 44) {
      puts("left");
      if (buf[5] < 227) {
       puts("left");
       if (buf[6] < 239) {
        puts("left");
        if (buf[7] < 215) {
         puts("left");
         if (buf[8] < 252) {
          puts("left");
          if (buf[9] < 59) {
           puts("left");
          } else {
           puts("right");
          }
         } else {
          puts("right");
          if (buf[9] < 6) {
           puts("left");
          } else {
           puts("right");
          }
         }
        } else {
         puts("right");
         if (buf[8] < 78) {
          puts("left");
          if (buf[9] < 47) {
           puts("left");
          } else {
           puts("right");
          }
         } else {
          puts("right");
          if (buf[9] < 123) {
           puts("left");
          } else {
           puts("right");
          }
         }
        }
       } else {
        puts("right");
        if (buf[7] < 19) {
         puts("left");
         if (buf[8] < 59) {
          puts("left");
          if (buf[9] < 117) {
           puts("left");
          } else {
           puts("right");
          }
         } else {
          puts("right");
          if (buf[9] < 215) {
           puts("left");
          } else {
           puts("right");
          }
         }
        } else {
         puts("right");
         if (buf[8] < 170) {
          puts("left");
          if (buf[9] < 18) {
           puts("left");
          } else {
           puts("right");
          }
         } else {
          puts("right");
          if (buf[9] < 112) {
           puts("left");
          } else {
           puts("right");
          }
         }
        }
       }
      } else {
       puts("right");
       if (buf[6] < 19) {
        puts("left");
        if (buf[7] < 247) {
         puts("left");
         if (buf[8] < 201) {
          puts("left");
          if (buf[9] < 176) {
           puts("left");
          } else {
           puts("right");
          }
         } else {
          puts("right");
          if (buf[9] < 131) {
           puts("left");
          } else {
           puts("right");
          }
         }
        } else {
         puts("right");
         if (buf[8] < 235) {
          puts("left");
          if (buf[9] < 149) {
           puts("left");
          } else {
           puts("right");
          }
         } else {
          puts("right");
          if (buf[9] < 1) {
           puts("left");
          } else {
           puts("right");
          }
         }
        }
       } else {
        puts("right");
        if (buf[7] < 13) {
         puts("left");
         if (buf[8] < 81) {
          puts("left");
          if (buf[9] < 248) {
           puts("left");
          } else {
           puts("right");
          }
         } else {
          puts("right");
          if (buf[9] < 209) {
           puts("left");
          } else {
           puts("right");
          }
         }
        } else {
         puts("right");
         if (buf[8] < 57) {
          puts("left");
          if (buf[9] < 58) {
           puts("left");
          } else {
           puts("right");
          }
         } else {
          puts("right");
          if (buf[9] < 67) {
           puts("left");
          } else {
           puts("right");
          }
         }
        }
       }
      }
     } else {
      puts("right");
      if (buf[5] < 224) {
       puts("left");
       if (buf[6] < 226) {
        puts("left");
        if (buf[7] < 200) {
         puts("left");
         if (buf[8] < 23) {
          puts("left");
          if (buf[9] < 95) {
           puts("left");
          } else {
           puts("right");
          }
         } else {
          puts("right");
          if (buf[9] < 80) {
           puts("left");
          } else {
           puts("right");
          }
         }
        } else {
         puts("right");
         if (buf[8] < 201) {
          puts("left");
          if (buf[9] < 0) {
           puts("left");
          } else {
           puts("right");
          }
         } else {
          puts("right");
          if (buf[9] < 166) {
           puts("left");
          } else {
           puts("right");
          }
         }
        }
       } else {
        puts("right");
        if (buf[7] < 73) {
         puts("left");
         if (buf[8] < 158) {
          puts("left");
          if (buf[9] < 10) {
           puts("left");
          } else {
           puts("right");
          }
         } else {
          puts("right");
          if (buf[9] < 102) {
           puts("left");
          } else {
           puts("right");
          }
         }
        } else {
         puts("right");
         if (buf[8] < 148) {
          puts("left");
          if (buf[9] < 35) {
           puts("left");
          } else {
           puts("right");
          }
         } else {
          puts("right");
          if (buf[9] < 209) {
           puts("left");
          } else {
           puts("right");
          }
         }
        }
       }
      } else {
       puts("right");
       if (buf[6] < 0) {
        puts("left");
        if (buf[7] < 126) {
         puts("left");
         if (buf[8] < 85) {
          puts("left");
          if (buf[9] < 46) {
           puts("left");
          } else {
           puts("right");
          }
         } else {
          puts("right");
          if (buf[9] < 169) {
           puts("left");
          } else {
           puts("right");
          }
         }
        } else {
         puts("right");
         if (buf[8] < 143) {
          puts("left");
          if (buf[9] < 118) {
           puts("left");
          } else {
           puts("right");
          }
         } else {
          puts("right");
          if (buf[9] < 129) {
           puts("left");
          } else {
           puts("right");
          }
         }
        }
       } else {
        puts("right");
        if (buf[7] < 31) {
         puts("left");
         if (buf[8] < 128) {
          puts("left");
          if (buf[9] < 169) {
           puts("left");
          } else {
           puts("right");
          }
         } else {
          puts("right");
          if (buf[9] < 188) {
           puts("left");
          } else {
           puts("right");
          }
         }
        } else {
         puts("right");
         if (buf[8] < 98) {
          puts("left");
          if (buf[9] < 88) {
           puts("left");
          } else {
           puts("right");
          }
         } else {
          puts("right");
          if (buf[9] < 46) {
           puts("left");
          } else {
           puts("right");
          }
         }
        }
       }
      }
     }
    }
   } else {
    puts("right");
    if (buf[3] < 214) {
     puts("left");
     if (buf[4] < 105) {
      puts("left");
      if (buf[5] < 66) {
       puts("left");
       if (buf[6] < 47) {
        puts("left");
        if (buf[7] < 186) {
         puts("left");
         if (buf[8] < 214) {
          puts("left");
          if (buf[9] < 88) {
           puts("left");
          } else {
           puts("right");
          }
         } else {
          puts("right");
          if (buf[9] < 22) {
           puts("left");
          } else {
           puts("right");
          }
         }
        } else {
         puts("right");
         if (buf[8] < 212) {
          puts("left");
          if (buf[9] < 226) {
           puts("left");
          } else {
           puts("right");
          }
         } else {
          puts("right");
          if (buf[9] < 9) {
           puts("left");
          } else {
           puts("right");
          }
         }
        }
       } else {
        puts("right");
        if (buf[7] < 186) {
         puts("left");
         if (buf[8] < 30) {
          puts("left");
          if (buf[9] < 100) {
           puts("left");
          } else {
           puts("right");
          }
         } else {
          puts("right");
          if (buf[9] < 140) {
           puts("left");
          } else {
           puts("right");
          }
         }
        } else {
         puts("right");
         if (buf[8] < 212) {
          puts("left");
          if (buf[9] < 168) {
           puts("left");
          } else {
           puts("right");
          }
         } else {
          puts("right");
          if (buf[9] < 113) {
           puts("left");
          } else {
           puts("right");
          }
         }
        }
       }
      } else {
       puts("right");
       if (buf[6] < 59) {
        puts("left");
        if (buf[7] < 144) {
         puts("left");
         if (buf[8] < 235) {
          puts("left");
          if (buf[9] < 194) {
           puts("left");
          } else {
           puts("right");
          }
         } else {
          puts("right");
          if (buf[9] < 184) {
           puts("left");
          } else {
           puts("right");
          }
         }
        } else {
         puts("right");
         if (buf[8] < 69) {
          puts("left");
          if (buf[9] < 187) {
           puts("left");
          } else {
           puts("right");
          }
         } else {
          puts("right");
          if (buf[9] < 17) {
           puts("left");
          } else {
           puts("right");
          }
         }
        }
       } else {
        puts("right");
        if (buf[7] < 140) {
         puts("left");
         if (buf[8] < 38) {
          puts("left");
          if (buf[9] < 216) {
           puts("left");
          } else {
           puts("right");
          }
         } else {
          puts("right");
          if (buf[9] < 150) {
           puts("left");
          } else {
           puts("right");
          }
         }
        } else {
         puts("right");
         if (buf[8] < 58) {
          puts("left");
          if (buf[9] < 23) {
           puts("left");
          } else {
           puts("right");
          }
         } else {
          puts("right");
          if (buf[9] < 36) {
           puts("left");
          } else {
           puts("right");
          }
         }
        }
       }
      }
     } else {
      puts("right");
      if (buf[5] < 29) {
       puts("left");
       if (buf[6] < 140) {
        puts("left");
        if (buf[7] < 158) {
         puts("left");
         if (buf[8] < 5) {
          puts("left");
          if (buf[9] < 250) {
           puts("left");
          } else {
           puts("right");
          }
         } else {
          puts("right");
          if (buf[9] < 60) {
           puts("left");
          } else {
           puts("right");
          }
         }
        } else {
         puts("right");
         if (buf[8] < 9) {
          puts("left");
          if (buf[9] < 109) {
           puts("left");
          } else {
           puts("right");
          }
         } else {
          puts("right");
          if (buf[9] < 170) {
           puts("left");
          } else {
           puts("right");
          }
         }
        }
       } else {
        puts("right");
        if (buf[7] < 50) {
         puts("left");
         if (buf[8] < 118) {
          puts("left");
          if (buf[9] < 74) {
           puts("left");
          } else {
           puts("right");
          }
         } else {
          puts("right");
          if (buf[9] < 186) {
           puts("left");
          } else {
           puts("right");
          }
         }
        } else {
         puts("right");
         if (buf[8] < 89) {
          puts("left");
          if (buf[9] < 24) {
           puts("left");
          } else {
           puts("right");
          }
         } else {
          puts("right");
          if (buf[9] < 195) {
           puts("left");
          } else {
           puts("right");
          }
         }
        }
       }
      } else {
       puts("right");
       if (buf[6] < 144) {
        puts("left");
        if (buf[7] < 37) {
         puts("left");
         if (buf[8] < 202) {
          puts("left");
          if (buf[9] < 31) {
           puts("left");
          } else {
           puts("right");
          }
         } else {
          puts("right");
          if (buf[9] < 4) {
           puts("left");
          } else {
           puts("right");
          }
         }
        } else {
         puts("right");
         if (buf[8] < 21) {
          puts("left");
          if (buf[9] < 3) {
           puts("left");
          } else {
           puts("right");
          }
         } else {
          puts("right");
          if (buf[9] < 132) {
           puts("left");
          } else {
           puts("right");
          }
         }
        }
       } else {
        puts("right");
        if (buf[7] < 182) {
         puts("left");
         if (buf[8] < 150) {
          puts("left");
          if (buf[9] < 133) {
           puts("left");
          } else {
           puts("right");
          }
         } else {
          puts("right");
          if (buf[9] < 240) {
           puts("left");
          } else {
           puts("right");
          }
         }
        } else {
         puts("right");
         if (buf[8] < 167) {
          puts("left");
          if (buf[9] < 15) {
           puts("left");
          } else {
           puts("right");
          }
         } else {
          puts("right");
          if (buf[9] < 93) {
           puts("left");
          } else {
           puts("right");
          }
         }
        }
       }
      }
     }
    } else {
     puts("right");
     if (buf[4] < 223) {
      puts("left");
      if (buf[5] < 78) {
       puts("left");
       if (buf[6] < 189) {
        puts("left");
        if (buf[7] < 95) {
         puts("left");
         if (buf[8] < 252) {
          puts("left");
          if (buf[9] < 246) {
           puts("left");
          } else {
           puts("right");
          }
         } else {
          puts("right");
          if (buf[9] < 90) {
           puts("left");
          } else {
           puts("right");
          }
         }
        } else {
         puts("right");
         if (buf[8] < 225) {
          puts("left");
          if (buf[9] < 11) {
           puts("left");
          } else {
           puts("right");
          }
         } else {
          puts("right");
          if (buf[9] < 249) {
           puts("left");
          } else {
           puts("right");
          }
         }
        }
       } else {
        puts("right");
        if (buf[7] < 207) {
         puts("left");
         if (buf[8] < 22) {
          puts("left");
          if (buf[9] < 139) {
           puts("left");
          } else {
           puts("right");
          }
         } else {
          puts("right");
          if (buf[9] < 161) {
           puts("left");
          } else {
           puts("right");
          }
         }
        } else {
         puts("right");
         if (buf[8] < 239) {
          puts("left");
          if (buf[9] < 8) {
           puts("left");
          } else {
           puts("right");
          }
         } else {
          puts("right");
          if (buf[9] < 190) {
           puts("left");
          } else {
           puts("right");
          }
         }
        }
       }
      } else {
       puts("right");
       if (buf[6] < 7) {
        puts("left");
        if (buf[7] < 25) {
         puts("left");
         if (buf[8] < 219) {
          puts("left");
          if (buf[9] < 66) {
           puts("left");
          } else {
           puts("right");
          }
         } else {
          puts("right");
          if (buf[9] < 100) {
           puts("left");
          } else {
           puts("right");
          }
         }
        } else {
         puts("right");
         if (buf[8] < 236) {
          puts("left");
          if (buf[9] < 178) {
           puts("left");
          } else {
           puts("right");
          }
         } else {
          puts("right");
          if (buf[9] < 16) {
           puts("left");
          } else {
           puts("right");
          }
         }
        }
       } else {
        puts("right");
        if (buf[7] < 231) {
         puts("left");
         if (buf[8] < 86) {
          puts("left");
          if (buf[9] < 70) {
           puts("left");
          } else {
           puts("right");
          }
         } else {
          puts("right");
          if (buf[9] < 23) {
           puts("left");
          } else {
           puts("right");
          }
         }
        } else {
         puts("right");
         if (buf[8] < 15) {
          puts("left");
          if (buf[9] < 207) {
           puts("left");
          } else {
           puts("right");
          }
         } else {
          puts("right");
          if (buf[9] < 54) {
           puts("left");
          } else {
           puts("right");
          }
         }
        }
       }
      }
     } else {
      puts("right");
      if (buf[5] < 228) {
       puts("left");
       if (buf[6] < 222) {
        puts("left");
        if (buf[7] < 125) {
         puts("left");
         if (buf[8] < 112) {
          puts("left");
          if (buf[9] < 135) {
           puts("left");
          } else {
           puts("right");
          }
         } else {
          puts("right");
          if (buf[9] < 157) {
           puts("left");
          } else {
           puts("right");
          }
         }
        } else {
         puts("right");
         if (buf[8] < 93) {
          puts("left");
          if (buf[9] < 11) {
           puts("left");
          } else {
           puts("right");
          }
         } else {
          puts("right");
          if (buf[9] < 134) {
           puts("left");
          } else {
           puts("right");
          }
         }
        }
       } else {
        puts("right");
        if (buf[7] < 21) {
         puts("left");
         if (buf[8] < 55) {
          puts("left");
          if (buf[9] < 111) {
           puts("left");
          } else {
           puts("right");
          }
         } else {
          puts("right");
          if (buf[9] < 100) {
           puts("left");
          } else {
           puts("right");
          }
         }
        } else {
         puts("right");
         if (buf[8] < 140) {
          puts("left");
          if (buf[9] < 35) {
           puts("left");
          } else {
           puts("right");
          }
         } else {
          puts("right");
          if (buf[9] < 252) {
           puts("left");
          } else {
           puts("right");
          }
         }
        }
       }
      } else {
       puts("right");
       if (buf[6] < 172) {
        puts("left");
        if (buf[7] < 237) {
         puts("left");
         if (buf[8] < 183) {
          puts("left");
          if (buf[9] < 59) {
           puts("left");
          } else {
           puts("right");
          }
         } else {
          puts("right");
          if (buf[9] < 245) {
           puts("left");
          } else {
           puts("right");
          }
         }
        } else {
         puts("right");
         if (buf[8] < 246) {
          puts("left");
          if (buf[9] < 33) {
           puts("left");
          } else {
           puts("right");
          }
         } else {
          puts("right");
          if (buf[9] < 87) {
           puts("left");
          } else {
           puts("right");
          }
         }
        }
       } else {
        puts("right");
        if (buf[7] < 56) {
         puts("left");
         if (buf[8] < 241) {
          puts("left");
          if (buf[9] < 95) {
           puts("left");
          } else {
           puts("right");
          }
         } else {
          puts("right");
          if (buf[9] < 178) {
           puts("left");
          } else {
           puts("right");
          }
         }
        } else {
         puts("right");
         if (buf[8] < 71) {
          puts("left");
          if (buf[9] < 151) {
           puts("left");
          } else {
           puts("right");
          }
         } else {
          puts("right");
          if (buf[9] < 126) {
           puts("left");
          } else {
           puts("right");
          }
         }
        }
       }
      }
     }
    }
   }
  }
 } else {
  puts("right");
  if (buf[1] < 6) {
   puts("left");
   if (buf[2] < 93) {
    puts("left");
    if (buf[3] < 96) {
     puts("left");
     if (buf[4] < 100) {
      puts("left");
      if (buf[5] < 186) {
       puts("left");
       if (buf[6] < 10) {
        puts("left");
        if (buf[7] < 180) {
         puts("left");
         if (buf[8] < 46) {
          puts("left");
          if (buf[9] < 156) {
           puts("left");
          } else {
           puts("right");
          }
         } else {
          puts("right");
          if (buf[9] < 156) {
           puts("left");
          } else {
           puts("right");
          }
         }
        } else {
         puts("right");
         if (buf[8] < 112) {
          puts("left");
          if (buf[9] < 108) {
           puts("left");
          } else {
           puts("right");
          }
         } else {
          puts("right");
          if (buf[9] < 126) {
           puts("left");
          } else {
           puts("right");
          }
         }
        }
       } else {
        puts("right");
        if (buf[7] < 215) {
         puts("left");
         if (buf[8] < 30) {
          puts("left");
          if (buf[9] < 198) {
           puts("left");
          } else {
           puts("right");
          }
         } else {
          puts("right");
          if (buf[9] < 48) {
           puts("left");
          } else {
           puts("right");
          }
         }
        } else {
         puts("right");
         if (buf[8] < 48) {
          puts("left");
          if (buf[9] < 175) {
           puts("left");
          } else {
           puts("right");
          }
         } else {
          puts("right");
          if (buf[9] < 157) {
           puts("left");
          } else {
           puts("right");
          }
         }
        }
       }
      } else {
       puts("right");
       if (buf[6] < 97) {
        puts("left");
        if (buf[7] < 164) {
         puts("left");
         if (buf[8] < 103) {
          puts("left");
          if (buf[9] < 135) {
           puts("left");
          } else {
           puts("right");
          }
         } else {
          puts("right");
          if (buf[9] < 157) {
           puts("left");
          } else {
           puts("right");
          }
         }
        } else {
         puts("right");
         if (buf[8] < 140) {
          puts("left");
          if (buf[9] < 33) {
           puts("left");
          } else {
           puts("right");
          }
         } else {
          puts("right");
          if (buf[9] < 110) {
           puts("left");
          } else {
           puts("right");
          }
         }
        }
       } else {
        puts("right");
        if (buf[7] < 52) {
         puts("left");
         if (buf[8] < 173) {
          puts("left");
          if (buf[9] < 177) {
           puts("left");
          } else {
           puts("right");
          }
         } else {
          puts("right");
          if (buf[9] < 133) {
           puts("left");
          } else {
           puts("right");
          }
         }
        } else {
         puts("right");
         if (buf[8] < 51) {
          puts("left");
          if (buf[9] < 216) {
           puts("left");
          } else {
           puts("right");
          }
         } else {
          puts("right");
          if (buf[9] < 191) {
           puts("left");
          } else {
           puts("right");
          }
         }
        }
       }
      }
     } else {
      puts("right");
      if (buf[5] < 146) {
       puts("left");
       if (buf[6] < 97) {
        puts("left");
        if (buf[7] < 190) {
         puts("left");
         if (buf[8] < 92) {
          puts("left");
          if (buf[9] < 233) {
           puts("left");
          } else {
           puts("right");
          }
         } else {
          puts("right");
          if (buf[9] < 225) {
           puts("left");
          } else {
           puts("right");
          }
         }
        } else {
         puts("right");
         if (buf[8] < 197) {
          puts("left");
          if (buf[9] < 185) {
           puts("left");
          } else {
           puts("right");
          }
         } else {
          puts("right");
          if (buf[9] < 122) {
           puts("left");
          } else {
           puts("right");
          }
         }
        }
       } else {
        puts("right");
        if (buf[7] < 127) {
         puts("left");
         if (buf[8] < 232) {
          puts("left");
          if (buf[9] < 179) {
           puts("left");
          } else {
           puts("right");
          }
         } else {
          puts("right");
          if (buf[9] < 129) {
           puts("left");
          } else {
           puts("right");
          }
         }
        } else {
         puts("right");
         if (buf[8] < 239) {
          puts("left");
          if (buf[9] < 239) {
           puts("left");
          } else {
           puts("right");
          }
         } else {
          puts("right");
          if (buf[9] < 96) {
           puts("left");
          } else {
           puts("right");
          }
         }
        }
       }
      } else {
       puts("right");
       if (buf[6] < 126) {
        puts("left");
        if (buf[7] < 54) {
         puts("left");
         if (buf[8] < 6) {
          puts("left");
          if (buf[9] < 90) {
           puts("left");
          } else {
           puts("right");
          }
         } else {
          puts("right");
          if (buf[9] < 70) {
           puts("left");
          } else {
           puts("right");
          }
         }
        } else {
         puts("right");
         if (buf[8] < 109) {
          puts("left");
          if (buf[9] < 86) {
           puts("left");
          } else {
           puts("right");
          }
         } else {
          puts("right");
          if (buf[9] < 95) {
           puts("left");
          } else {
           puts("right");
          }
         }
        }
       } else {
        puts("right");
        if (buf[7] < 130) {
         puts("left");
         if (buf[8] < 242) {
          puts("left");
          if (buf[9] < 106) {
           puts("left");
          } else {
           puts("right");
          }
         } else {
          puts("right");
          if (buf[9] < 33) {
           puts("left");
          } else {
           puts("right");
          }
         }
        } else {
         puts("right");
         if (buf[8] < 61) {
          puts("left");
          if (buf[9] < 48) {
           puts("left");
          } else {
           puts("right");
          }
         } else {
          puts("right");
          if (buf[9] < 1) {
           puts("left");
          } else {
           puts("right");
          }
         }
        }
       }
      }
     }
    } else {
     puts("right");
     if (buf[4] < 38) {
      puts("left");
      if (buf[5] < 95) {
       puts("left");
       if (buf[6] < 97) {
        puts("left");
        if (buf[7] < 76) {
         puts("left");
         if (buf[8] < 248) {
          puts("left");
          if (buf[9] < 3) {
           puts("left");
          } else {
           puts("right");
          }
         } else {
          puts("right");
          if (buf[9] < 198) {
           puts("left");
          } else {
           puts("right");
          }
         }
        } else {
         puts("right");
         if (buf[8] < 15) {
          puts("left");
          if (buf[9] < 28) {
           puts("left");
          } else {
           puts("right");
          }
         } else {
          puts("right");
          if (buf[9] < 102) {
           puts("left");
          } else {
           puts("right");
          }
         }
        }
       } else {
        puts("right");
        if (buf[7] < 141) {
         puts("left");
         if (buf[8] < 160) {
          puts("left");
          if (buf[9] < 150) {
           puts("left");
          } else {
           puts("right");
          }
         } else {
          puts("right");
          if (buf[9] < 228) {
           puts("left");
          } else {
           puts("right");
          }
         }
        } else {
         puts("right");
         if (buf[8] < 26) {
          puts("left");
          if (buf[9] < 185) {
           puts("left");
          } else {
           puts("right");
          }
         } else {
          puts("right");
          if (buf[9] < 246) {
           puts("left");
          } else {
           puts("right");
          }
         }
        }
       }
      } else {
       puts("right");
       if (buf[6] < 46) {
        puts("left");
        if (buf[7] < 65) {
         puts("left");
         if (buf[8] < 130) {
          puts("left");
          if (buf[9] < 32) {
           puts("left");
          } else {
           puts("right");
          }
         } else {
          puts("right");
          if (buf[9] < 105) {
           puts("left");
          } else {
           puts("right");
          }
         }
        } else {
         puts("right");
         if (buf[8] < 60) {
          puts("left");
          if (buf[9] < 114) {
           puts("left");
          } else {
           puts("right");
          }
         } else {
          puts("right");
          if (buf[9] < 183) {
           puts("left");
          } else {
           puts("right");
          }
         }
        }
       } else {
        puts("right");
        if (buf[7] < 167) {
         puts("left");
         if (buf[8] < 204) {
          puts("left");
          if (buf[9] < 37) {
           puts("left");
          } else {
           puts("right");
          }
         } else {
          puts("right");
          if (buf[9] < 217) {
           puts("left");
          } else {
           puts("right");
          }
         }
        } else {
         puts("right");
         if (buf[8] < 35) {
          puts("left");
          if (buf[9] < 109) {
           puts("left");
          } else {
           puts("right");
          }
         } else {
          puts("right");
          if (buf[9] < 219) {
           puts("left");
          } else {
           puts("right");
          }
         }
        }
       }
      }
     } else {
      puts("right");
      if (buf[5] < 208) {
       puts("left");
       if (buf[6] < 79) {
        puts("left");
        if (buf[7] < 177) {
         puts("left");
         if (buf[8] < 11) {
          puts("left");
          if (buf[9] < 247) {
           puts("left");
          } else {
           puts("right");
          }
         } else {
          puts("right");
          if (buf[9] < 177) {
           puts("left");
          } else {
           puts("right");
          }
         }
        } else {
         puts("right");
         if (buf[8] < 0) {
          puts("left");
          if (buf[9] < 177) {
           puts("left");
          } else {
           puts("right");
          }
         } else {
          puts("right");
          if (buf[9] < 124) {
           puts("left");
          } else {
           puts("right");
          }
         }
        }
       } else {
        puts("right");
        if (buf[7] < 94) {
         puts("left");
         if (buf[8] < 9) {
          puts("left");
          if (buf[9] < 158) {
           puts("left");
          } else {
           puts("right");
          }
         } else {
          puts("right");
          if (buf[9] < 225) {
           puts("left");
          } else {
           puts("right");
          }
         }
        } else {
         puts("right");
         if (buf[8] < 157) {
          puts("left");
          if (buf[9] < 19) {
           puts("left");
          } else {
           puts("right");
          }
         } else {
          puts("right");
          if (buf[9] < 47) {
           puts("left");
          } else {
           puts("right");
          }
         }
        }
       }
      } else {
       puts("right");
       if (buf[6] < 41) {
        puts("left");
        if (buf[7] < 175) {
         puts("left");
         if (buf[8] < 124) {
          puts("left");
          if (buf[9] < 223) {
           puts("left");
          } else {
           puts("right");
          }
         } else {
          puts("right");
          if (buf[9] < 10) {
           puts("left");
          } else {
           puts("right");
          }
         }
        } else {
         puts("right");
         if (buf[8] < 173) {
          puts("left");
          if (buf[9] < 33) {
           puts("left");
          } else {
           puts("right");
          }
         } else {
          puts("right");
          if (buf[9] < 85) {
           puts("left");
          } else {
           puts("right");
          }
         }
        }
       } else {
        puts("right");
        if (buf[7] < 244) {
         puts("left");
         if (buf[8] < 93) {
          puts("left");
          if (buf[9] < 215) {
           puts("left");
          } else {
           puts("right");
          }
         } else {
          puts("right");
          if (buf[9] < 170) {
           puts("left");
          } else {
           puts("right");
          }
         }
        } else {
         puts("right");
         if (buf[8] < 14) {
          puts("left");
          if (buf[9] < 224) {
           puts("left");
          } else {
           puts("right");
          }
         } else {
          puts("right");
          if (buf[9] < 201) {
           puts("left");
          } else {
           puts("right");
          }
         }
        }
       }
      }
     }
    }
   } else {
    puts("right");
    if (buf[3] < 242) {
     puts("left");
     if (buf[4] < 31) {
      puts("left");
      if (buf[5] < 80) {
       puts("left");
       if (buf[6] < 221) {
        puts("left");
        if (buf[7] < 253) {
         puts("left");
         if (buf[8] < 196) {
          puts("left");
          if (buf[9] < 91) {
           puts("left");
          } else {
           puts("right");
          }
         } else {
          puts("right");
          if (buf[9] < 243) {
           puts("left");
          } else {
           puts("right");
          }
         }
        } else {
         puts("right");
         if (buf[8] < 226) {
          puts("left");
          if (buf[9] < 99) {
           puts("left");
          } else {
           puts("right");
          }
         } else {
          puts("right");
          if (buf[9] < 250) {
           puts("left");
          } else {
           puts("right");
          }
         }
        }
       } else {
        puts("right");
        if (buf[7] < 126) {
         puts("left");
         if (buf[8] < 114) {
          puts("left");
          if (buf[9] < 43) {
           puts("left");
          } else {
           puts("right");
          }
         } else {
          puts("right");
          if (buf[9] < 195) {
           puts("left");
          } else {
           puts("right");
          }
         }
        } else {
         puts("right");
         if (buf[8] < 253) {
          puts("left");
          if (buf[9] < 190) {
           puts("left");
          } else {
           puts("right");
          }
         } else {
          puts("right");
          if (buf[9] < 25) {
           puts("left");
          } else {
           puts("right");
          }
         }
        }
       }
      } else {
       puts("right");
       if (buf[6] < 79) {
        puts("left");
        if (buf[7] < 132) {
         puts("left");
         if (buf[8] < 132) {
          puts("left");
          if (buf[9] < 93) {
           puts("left");
          } else {
           puts("right");
          }
         } else {
          puts("right");
          if (buf[9] < 254) {
           puts("left");
          } else {
           puts("right");
          }
         }
        } else {
         puts("right");
         if (buf[8] < 212) {
          puts("left");
          if (buf[9] < 233) {
           puts("left");
          } else {
           puts("right");
          }
         } else {
          puts("right");
          if (buf[9] < 215) {
           puts("left");
          } else {
           puts("right");
          }
         }
        }
       } else {
        puts("right");
        if (buf[7] < 98) {
         puts("left");
         if (buf[8] < 119) {
          puts("left");
          if (buf[9] < 154) {
           puts("left");
          } else {
           puts("right");
          }
         } else {
          puts("right");
          if (buf[9] < 183) {
           puts("left");
          } else {
           puts("right");
          }
         }
        } else {
         puts("right");
         if (buf[8] < 105) {
          puts("left");
          if (buf[9] < 187) {
           puts("left");
          } else {
           puts("right");
          }
         } else {
          puts("right");
          if (buf[9] < 167) {
           puts("left");
          } else {
           puts("right");
          }
         }
        }
       }
      }
     } else {
      puts("right");
      if (buf[5] < 219) {
       puts("left");
       if (buf[6] < 73) {
        puts("left");
        if (buf[7] < 237) {
         puts("left");
         if (buf[8] < 123) {
          puts("left");
          if (buf[9] < 5) {
           puts("left");
          } else {
           puts("right");
          }
         } else {
          puts("right");
          if (buf[9] < 197) {
           puts("left");
          } else {
           puts("right");
          }
         }
        } else {
         puts("right");
         if (buf[8] < 183) {
          puts("left");
          if (buf[9] < 139) {
           puts("left");
          } else {
           puts("right");
          }
         } else {
          puts("right");
          if (buf[9] < 174) {
           puts("left");
          } else {
           puts("right");
          }
         }
        }
       } else {
        puts("right");
        if (buf[7] < 142) {
         puts("left");
         if (buf[8] < 236) {
          puts("left");
          if (buf[9] < 69) {
           puts("left");
          } else {
           puts("right");
          }
         } else {
          puts("right");
          if (buf[9] < 105) {
           puts("left");
          } else {
           puts("right");
          }
         }
        } else {
         puts("right");
         if (buf[8] < 206) {
          puts("left");
          if (buf[9] < 114) {
           puts("left");
          } else {
           puts("right");
          }
         } else {
          puts("right");
          if (buf[9] < 108) {
           puts("left");
          } else {
           puts("right");
          }
         }
        }
       }
      } else {
       puts("right");
       if (buf[6] < 254) {
        puts("left");
        if (buf[7] < 108) {
         puts("left");
         if (buf[8] < 79) {
          puts("left");
          if (buf[9] < 37) {
           puts("left");
          } else {
           puts("right");
          }
         } else {
          puts("right");
          if (buf[9] < 189) {
           puts("left");
          } else {
           puts("right");
          }
         }
        } else {
         puts("right");
         if (buf[8] < 61) {
          puts("left");
          if (buf[9] < 154) {
           puts("left");
          } else {
           puts("right");
          }
         } else {
          puts("right");
          if (buf[9] < 35) {
           puts("left");
          } else {
           puts("right");
          }
         }
        }
       } else {
        puts("right");
        if (buf[7] < 140) {
         puts("left");
         if (buf[8] < 242) {
          puts("left");
          if (buf[9] < 185) {
           puts("left");
          } else {
           puts("right");
          }
         } else {
          puts("right");
          if (buf[9] < 62) {
           puts("left");
          } else {
           puts("right");
          }
         }
        } else {
         puts("right");
         if (buf[8] < 157) {
          puts("left");
          if (buf[9] < 167) {
           puts("left");
          } else {
           puts("right");
          }
         } else {
          puts("right");
          if (buf[9] < 73) {
           puts("left");
          } else {
           puts("right");
          }
         }
        }
       }
      }
     }
    } else {
     puts("right");
     if (buf[4] < 125) {
      puts("left");
      if (buf[5] < 243) {
       puts("left");
       if (buf[6] < 100) {
        puts("left");
        if (buf[7] < 0) {
         puts("left");
         if (buf[8] < 133) {
          puts("left");
          if (buf[9] < 115) {
           puts("left");
          } else {
           puts("right");
          }
         } else {
          puts("right");
          if (buf[9] < 200) {
           puts("left");
          } else {
           puts("right");
          }
         }
        } else {
         puts("right");
         if (buf[8] < 149) {
          puts("left");
          if (buf[9] < 147) {
           puts("left");
          } else {
           puts("right");
          }
         } else {
          puts("right");
          if (buf[9] < 25) {
           puts("left");
          } else {
           puts("right");
          }
         }
        }
       } else {
        puts("right");
        if (buf[7] < 8) {
         puts("left");
         if (buf[8] < 240) {
          puts("left");
          if (buf[9] < 182) {
           puts("left");
          } else {
           puts("right");
          }
         } else {
          puts("right");
          if (buf[9] < 127) {
           puts("left");
          } else {
           puts("right");
          }
         }
        } else {
         puts("right");
         if (buf[8] < 193) {
          puts("left");
          if (buf[9] < 154) {
           puts("left");
          } else {
           puts("right");
          }
         } else {
          puts("right");
          if (buf[9] < 78) {
           puts("left");
          } else {
           puts("right");
          }
         }
        }
       }
      } else {
       puts("right");
       if (buf[6] < 7) {
        puts("left");
        if (buf[7] < 41) {
         puts("left");
         if (buf[8] < 58) {
          puts("left");
          if (buf[9] < 118) {
           puts("left");
          } else {
           puts("right");
          }
         } else {
          puts("right");
          if (buf[9] < 20) {
           puts("left");
          } else {
           puts("right");
          }
         }
        } else {
         puts("right");
         if (buf[8] < 221) {
          puts("left");
          if (buf[9] < 145) {
           puts("left");
          } else {
           puts("right");
          }
         } else {
          puts("right");
          if (buf[9] < 172) {
           puts("left");
          } else {
           puts("right");
          }
         }
        }
       } else {
        puts("right");
        if (buf[7] < 171) {
         puts("left");
         if (buf[8] < 105) {
          puts("left");
          if (buf[9] < 251) {
           puts("left");
          } else {
           puts("right");
          }
         } else {
          puts("right");
          if (buf[9] < 6) {
           puts("left");
          } else {
           puts("right");
          }
         }
        } else {
         puts("right");
         if (buf[8] < 11) {
          puts("left");
          if (buf[9] < 238) {
           puts("left");
          } else {
           puts("right");
          }
         } else {
          puts("right");
          if (buf[9] < 75) {
           puts("left");
          } else {
           puts("right");
          }
         }
        }
       }
      }
     } else {
      puts("right");
      if (buf[5] < 109) {
       puts("left");
       if (buf[6] < 237) {
        puts("left");
        if (buf[7] < 12) {
         puts("left");
         if (buf[8] < 181) {
          puts("left");
          if (buf[9] < 233) {
           puts("left");
          } else {
           puts("right");
          }
         } else {
          puts("right");
          if (buf[9] < 186) {
           puts("left");
          } else {
           puts("right");
          }
         }
        } else {
         puts("right");
         if (buf[8] < 140) {
          puts("left");
          if (buf[9] < 46) {
           puts("left");
          } else {
           puts("right");
          }
         } else {
          puts("right");
          if (buf[9] < 83) {
           puts("left");
          } else {
           puts("right");
          }
         }
        }
       } else {
        puts("right");
        if (buf[7] < 165) {
         puts("left");
         if (buf[8] < 33) {
          puts("left");
          if (buf[9] < 101) {
           puts("left");
          } else {
           puts("right");
          }
         } else {
          puts("right");
          if (buf[9] < 225) {
           puts("left");
          } else {
           puts("right");
          }
         }
        } else {
         puts("right");
         if (buf[8] < 36) {
          puts("left");
          if (buf[9] < 254) {
           puts("left");
          } else {
           puts("right");
          }
         } else {
          puts("right");
          if (buf[9] < 208) {
           puts("left");
          } else {
           puts("right");
          }
         }
        }
       }
      } else {
       puts("right");
       if (buf[6] < 202) {
        puts("left");
        if (buf[7] < 136) {
         puts("left");
         if (buf[8] < 146) {
          puts("left");
          if (buf[9] < 92) {
           puts("left");
          } else {
           puts("right");
          }
         } else {
          puts("right");
          if (buf[9] < 115) {
           puts("left");
          } else {
           puts("right");
          }
         }
        } else {
         puts("right");
         if (buf[8] < 218) {
          puts("left");
          if (buf[9] < 223) {
           puts("left");
          } else {
           puts("right");
          }
         } else {
          puts("right");
          if (buf[9] < 3) {
           puts("left");
          } else {
           puts("right");
          }
         }
        }
       } else {
        puts("right");
        if (buf[7] < 90) {
         puts("left");
         if (buf[8] < 189) {
          puts("left");
          if (buf[9] < 246) {
           puts("left");
          } else {
           puts("right");
          }
         } else {
          puts("right");
          if (buf[9] < 33) {
           puts("left");
          } else {
           puts("right");
          }
         }
        } else {
         puts("right");
         if (buf[8] < 74) {
          puts("left");
          if (buf[9] < 11) {
           puts("left");
          } else {
           puts("right");
          }
         } else {
          puts("right");
          if (buf[9] < 224) {
           puts("left");
          } else {
           puts("right");
          }
         }
        }
       }
      }
     }
    }
   }
  } else {
   puts("right");
   if (buf[2] < 67) {
    puts("left");
    if (buf[3] < 94) {
     puts("left");
     if (buf[4] < 145) {
      puts("left");
      if (buf[5] < 232) {
       puts("left");
       if (buf[6] < 123) {
        puts("left");
        if (buf[7] < 62) {
         puts("left");
         if (buf[8] < 28) {
          puts("left");
          if (buf[9] < 82) {
           puts("left");
          } else {
           puts("right");
          }
         } else {
          puts("right");
          if (buf[9] < 141) {
           puts("left");
          } else {
           puts("right");
          }
         }
        } else {
         puts("right");
         if (buf[8] < 240) {
          puts("left");
          if (buf[9] < 74) {
           puts("left");
          } else {
           puts("right");
          }
         } else {
          puts("right");
          if (buf[9] < 133) {
           puts("left");
          } else {
           puts("right");
          }
         }
        }
       } else {
        puts("right");
        if (buf[7] < 34) {
         puts("left");
         if (buf[8] < 100) {
          puts("left");
          if (buf[9] < 91) {
           puts("left");
          } else {
           puts("right");
          }
         } else {
          puts("right");
          if (buf[9] < 15) {
           puts("left");
          } else {
           puts("right");
          }
         }
        } else {
         puts("right");
         if (buf[8] < 54) {
          puts("left");
          if (buf[9] < 57) {
           puts("left");
          } else {
           puts("right");
          }
         } else {
          puts("right");
          if (buf[9] < 140) {
           puts("left");
          } else {
           puts("right");
          }
         }
        }
       }
      } else {
       puts("right");
       if (buf[6] < 68) {
        puts("left");
        if (buf[7] < 199) {
         puts("left");
         if (buf[8] < 25) {
          puts("left");
          if (buf[9] < 181) {
           puts("left");
          } else {
           puts("right");
          }
         } else {
          puts("right");
          if (buf[9] < 153) {
           puts("left");
          } else {
           puts("right");
          }
         }
        } else {
         puts("right");
         if (buf[8] < 17) {
          puts("left");
          if (buf[9] < 22) {
           puts("left");
          } else {
           puts("right");
          }
         } else {
          puts("right");
          if (buf[9] < 16) {
           puts("left");
          } else {
           puts("right");
          }
         }
        }
       } else {
        puts("right");
        if (buf[7] < 62) {
         puts("left");
         if (buf[8] < 209) {
          puts("left");
          if (buf[9] < 75) {
           puts("left");
          } else {
           puts("right");
          }
         } else {
          puts("right");
          if (buf[9] < 166) {
           puts("left");
          } else {
           puts("right");
          }
         }
        } else {
         puts("right");
         if (buf[8] < 40) {
          puts("left");
          if (buf[9] < 175) {
           puts("left");
          } else {
           puts("right");
          }
         } else {
          puts("right");
          if (buf[9] < 249) {
           puts("left");
          } else {
           puts("right");
          }
         }
        }
       }
      }
     } else {
      puts("right");
      if (buf[5] < 28) {
       puts("left");
       if (buf[6] < 121) {
        puts("left");
        if (buf[7] < 164) {
         puts("left");
         if (buf[8] < 39) {
          puts("left");
          if (buf[9] < 229) {
           puts("left");
          } else {
           puts("right");
          }
         } else {
          puts("right");
          if (buf[9] < 166) {
           puts("left");
          } else {
           puts("right");
          }
         }
        } else {
         puts("right");
         if (buf[8] < 57) {
          puts("left");
          if (buf[9] < 235) {
           puts("left");
          } else {
           puts("right");
          }
         } else {
          puts("right");
          if (buf[9] < 225) {
           puts("left");
          } else {
           puts("right");
          }
         }
        }
       } else {
        puts("right");
        if (buf[7] < 220) {
         puts("left");
         if (buf[8] < 79) {
          puts("left");
          if (buf[9] < 188) {
           puts("left");
          } else {
           puts("right");
          }
         } else {
          puts("right");
          if (buf[9] < 95) {
           puts("left");
          } else {
           puts("right");
          }
         }
        } else {
         puts("right");
         if (buf[8] < 12) {
          puts("left");
          if (buf[9] < 182) {
           puts("left");
          } else {
           puts("right");
          }
         } else {
          puts("right");
          if (buf[9] < 5) {
           puts("left");
          } else {
           puts("right");
          }
         }
        }
       }
      } else {
       puts("right");
       if (buf[6] < 190) {
        puts("left");
        if (buf[7] < 39) {
         puts("left");
         if (buf[8] < 164) {
          puts("left");
          if (buf[9] < 177) {
           puts("left");
          } else {
           puts("right");
          }
         } else {
          puts("right");
          if (buf[9] < 72) {
           puts("left");
          } else {
           puts("right");
          }
         }
        } else {
         puts("right");
         if (buf[8] < 65) {
          puts("left");
          if (buf[9] < 220) {
           puts("left");
          } else {
           puts("right");
          }
         } else {
          puts("right");
          if (buf[9] < 95) {
           puts("left");
          } else {
           puts("right");
          }
         }
        }
       } else {
        puts("right");
        if (buf[7] < 237) {
         puts("left");
         if (buf[8] < 244) {
          puts("left");
          if (buf[9] < 179) {
           puts("left");
          } else {
           puts("right");
          }
         } else {
          puts("right");
          if (buf[9] < 56) {
           puts("left");
          } else {
           puts("right");
          }
         }
        } else {
         puts("right");
         if (buf[8] < 162) {
          puts("left");
          if (buf[9] < 95) {
           puts("left");
          } else {
           puts("right");
          }
         } else {
          puts("right");
          if (buf[9] < 252) {
           puts("left");
          } else {
           puts("right");
          }
         }
        }
       }
      }
     }
    } else {
     puts("right");
     if (buf[4] < 72) {
      puts("left");
      if (buf[5] < 173) {
       puts("left");
       if (buf[6] < 193) {
        puts("left");
        if (buf[7] < 100) {
         puts("left");
         if (buf[8] < 252) {
          puts("left");
          if (buf[9] < 44) {
           puts("left");
          } else {
           puts("right");
          }
         } else {
          puts("right");
          if (buf[9] < 169) {
           puts("left");
          } else {
           puts("right");
          }
         }
        } else {
         puts("right");
         if (buf[8] < 156) {
          puts("left");
          if (buf[9] < 18) {
           puts("left");
          } else {
           puts("right");
          }
         } else {
          puts("right");
          if (buf[9] < 203) {
           puts("left");
          } else {
           puts("right");
          }
         }
        }
       } else {
        puts("right");
        if (buf[7] < 75) {
         puts("left");
         if (buf[8] < 23) {
          puts("left");
          if (buf[9] < 113) {
           puts("left");
          } else {
           puts("right");
          }
         } else {
          puts("right");
          if (buf[9] < 144) {
           puts("left");
          } else {
           puts("right");
          }
         }
        } else {
         puts("right");
         if (buf[8] < 172) {
          puts("left");
          if (buf[9] < 177) {
           puts("left");
          } else {
           puts("right");
          }
         } else {
          puts("right");
          if (buf[9] < 76) {
           puts("left");
          } else {
           puts("right");
          }
         }
        }
       }
      } else {
       puts("right");
       if (buf[6] < 242) {
        puts("left");
        if (buf[7] < 110) {
         puts("left");
         if (buf[8] < 106) {
          puts("left");
          if (buf[9] < 3) {
           puts("left");
          } else {
           puts("right");
          }
         } else {
          puts("right");
          if (buf[9] < 184) {
           puts("left");
          } else {
           puts("right");
          }
         }
        } else {
         puts("right");
         if (buf[8] < 161) {
          puts("left");
          if (buf[9] < 14) {
           puts("left");
          } else {
           puts("right");
          }
         } else {
          puts("right");
          if (buf[9] < 145) {
           puts("left");
          } else {
           puts("right");
          }
         }
        }
       } else {
        puts("right");
        if (buf[7] < 251) {
         puts("left");
         if (buf[8] < 102) {
          puts("left");
          if (buf[9] < 138) {
           puts("left");
          } else {
           puts("right");
          }
         } else {
          puts("right");
          if (buf[9] < 216) {
           puts("left");
          } else {
           puts("right");
          }
         }
        } else {
         puts("right");
         if (buf[8] < 72) {
          puts("left");
          if (buf[9] < 89) {
           puts("left");
          } else {
           puts("right");
          }
         } else {
          puts("right");
          if (buf[9] < 1) {
           puts("left");
          } else {
           puts("right");
          }
         }
        }
       }
      }
     } else {
      puts("right");
      if (buf[5] < 30) {
       puts("left");
       if (buf[6] < 123) {
        puts("left");
        if (buf[7] < 229) {
         puts("left");
         if (buf[8] < 5) {
          puts("left");
          if (buf[9] < 209) {
           puts("left");
          } else {
           puts("right");
          }
         } else {
          puts("right");
          if (buf[9] < 36) {
           puts("left");
          } else {
           puts("right");
          }
         }
        } else {
         puts("right");
         if (buf[8] < 4) {
          puts("left");
          if (buf[9] < 175) {
           puts("left");
          } else {
           puts("right");
          }
         } else {
          puts("right");
          if (buf[9] < 122) {
           puts("left");
          } else {
           puts("right");
          }
         }
        }
       } else {
        puts("right");
        if (buf[7] < 195) {
         puts("left");
         if (buf[8] < 215) {
          puts("left");
          if (buf[9] < 104) {
           puts("left");
          } else {
           puts("right");
          }
         } else {
          puts("right");
          if (buf[9] < 195) {
           puts("left");
          } else {
           puts("right");
          }
         }
        } else {
         puts("right");
         if (buf[8] < 172) {
          puts("left");
          if (buf[9] < 214) {
           puts("left");
          } else {
           puts("right");
          }
         } else {
          puts("right");
          if (buf[9] < 161) {
           puts("left");
          } else {
           puts("right");
          }
         }
        }
       }
      } else {
       puts("right");
       if (buf[6] < 25) {
        puts("left");
        if (buf[7] < 188) {
         puts("left");
         if (buf[8] < 153) {
          puts("left");
          if (buf[9] < 215) {
           puts("left");
          } else {
           puts("right");
          }
         } else {
          puts("right");
          if (buf[9] < 239) {
           puts("left");
          } else {
           puts("right");
          }
         }
        } else {
         puts("right");
         if (buf[8] < 120) {
          puts("left");
          if (buf[9] < 145) {
           puts("left");
          } else {
           puts("right");
          }
         } else {
          puts("right");
          if (buf[9] < 208) {
           puts("left");
          } else {
           puts("right");
          }
         }
        }
       } else {
        puts("right");
        if (buf[7] < 42) {
         puts("left");
         if (buf[8] < 92) {
          puts("left");
          if (buf[9] < 84) {
           puts("left");
          } else {
           puts("right");
          }
         } else {
          puts("right");
          if (buf[9] < 41) {
           puts("left");
          } else {
           puts("right");
          }
         }
        } else {
         puts("right");
         if (buf[8] < 254) {
          puts("left");
          if (buf[9] < 26) {
           puts("left");
          } else {
           puts("right");
          }
         } else {
          puts("right");
          if (buf[9] < 107) {
           puts("left");
          } else {
           puts("right");
          }
         }
        }
       }
      }
     }
    }
   } else {
    puts("right");
    if (buf[3] < 161) {
     puts("left");
     if (buf[4] < 84) {
      puts("left");
      if (buf[5] < 134) {
       puts("left");
       if (buf[6] < 197) {
        puts("left");
        if (buf[7] < 185) {
         puts("left");
         if (buf[8] < 247) {
          puts("left");
          if (buf[9] < 222) {
           puts("left");
          } else {
           puts("right");
          }
         } else {
          puts("right");
          if (buf[9] < 77) {
           puts("left");
          } else {
           puts("right");
          }
         }
        } else {
         puts("right");
         if (buf[8] < 203) {
          puts("left");
          if (buf[9] < 159) {
           puts("left");
          } else {
           puts("right");
          }
         } else {
          puts("right");
          if (buf[9] < 63) {
           puts("left");
          } else {
           puts("right");
          }
         }
        }
       } else {
        puts("right");
        if (buf[7] < 7) {
         puts("left");
         if (buf[8] < 127) {
          puts("left");
          if (buf[9] < 54) {
           puts("left");
          } else {
           puts("right");
          }
         } else {
          puts("right");
          if (buf[9] < 63) {
           puts("left");
          } else {
           puts("right");
          }
         }
        } else {
         puts("right");
         if (buf[8] < 205) {
          puts("left");
          if (buf[9] < 166) {
           puts("left");
          } else {
           puts("right");
          }
         } else {
          puts("right");
          if (buf[9] < 217) {
           puts("left");
          } else {
           puts("right");
          }
         }
        }
       }
      } else {
       puts("right");
       if (buf[6] < 22) {
        puts("left");
        if (buf[7] < 2) {
         puts("left");
         if (buf[8] < 233) {
          puts("left");
          if (buf[9] < 190) {
           puts("left");
          } else {
           puts("right");
          }
         } else {
          puts("right");
          if (buf[9] < 34) {
           puts("left");
          } else {
           puts("right");
          }
         }
        } else {
         puts("right");
         if (buf[8] < 63) {
          puts("left");
          if (buf[9] < 2) {
           puts("left");
          } else {
           puts("right");
          }
         } else {
          puts("right");
          if (buf[9] < 172) {
           puts("left");
          } else {
           puts("right");
          }
         }
        }
       } else {
        puts("right");
        if (buf[7] < 147) {
         puts("left");
         if (buf[8] < 212) {
          puts("left");
          if (buf[9] < 46) {
           puts("left");
          } else {
           puts("right");
          }
         } else {
          puts("right");
          if (buf[9] < 195) {
           puts("left");
          } else {
           puts("right");
          }
         }
        } else {
         puts("right");
         if (buf[8] < 115) {
          puts("left");
          if (buf[9] < 223) {
           puts("left");
          } else {
           puts("right");
          }
         } else {
          puts("right");
          if (buf[9] < 13) {
           puts("left");
          } else {
           puts("right");
          }
         }
        }
       }
      }
     } else {
      puts("right");
      if (buf[5] < 165) {
       puts("left");
       if (buf[6] < 31) {
        puts("left");
        if (buf[7] < 42) {
         puts("left");
         if (buf[8] < 211) {
          puts("left");
          if (buf[9] < 37) {
           puts("left");
          } else {
           puts("right");
          }
         } else {
          puts("right");
          if (buf[9] < 197) {
           puts("left");
          } else {
           puts("right");
          }
         }
        } else {
         puts("right");
         if (buf[8] < 89) {
          puts("left");
          if (buf[9] < 148) {
           puts("left");
          } else {
           puts("right");
          }
         } else {
          puts("right");
          if (buf[9] < 214) {
           puts("left");
          } else {
           puts("right");
          }
         }
        }
       } else {
        puts("right");
        if (buf[7] < 127) {
         puts("left");
         if (buf[8] < 196) {
          puts("left");
          if (buf[9] < 95) {
           puts("left");
          } else {
           puts("right");
          }
         } else {
          puts("right");
          if (buf[9] < 38) {
           puts("left");
          } else {
           puts("right");
          }
         }
        } else {
         puts("right");
         if (buf[8] < 254) {
          puts("left");
          if (buf[9] < 253) {
           puts("left");
          } else {
           puts("right");
          }
         } else {
          puts("right");
          if (buf[9] < 103) {
           puts("left");
          } else {
           puts("right");
          }
         }
        }
       }
      } else {
       puts("right");
       if (buf[6] < 217) {
        puts("left");
        if (buf[7] < 84) {
         puts("left");
         if (buf[8] < 88) {
          puts("left");
          if (buf[9] < 116) {
           puts("left");
          } else {
           puts("right");
          }
         } else {
          puts("right");
          if (buf[9] < 168) {
           puts("left");
          } else {
           puts("right");
          }
         }
        } else {
         puts("right");
         if (buf[8] < 66) {
          puts("left");
          if (buf[9] < 128) {
           puts("left");
          } else {
           puts("right");
          }
         } else {
          puts("right");
          if (buf[9] < 141) {
           puts("left");
          } else {
           puts("right");
          }
         }
        }
       } else {
        puts("right");
        if (buf[7] < 40) {
         puts("left");
         if (buf[8] < 126) {
          puts("left");
          if (buf[9] < 7) {
           puts("left");
          } else {
           puts("right");
          }
         } else {
          puts("right");
          if (buf[9] < 170) {
           puts("left");
          } else {
           puts("right");
          }
         }
        } else {
         puts("right");
         if (buf[8] < 200) {
          puts("left");
          if (buf[9] < 37) {
           puts("left");
          } else {
           puts("right");
          }
         } else {
          puts("right");
          if (buf[9] < 105) {
           puts("left");
          } else {
           puts("right");
          }
         }
        }
       }
      }
     }
    } else {
     puts("right");
     if (buf[4] < 255) {
      puts("left");
      if (buf[5] < 93) {
       puts("left");
       if (buf[6] < 132) {
        puts("left");
        if (buf[7] < 223) {
         puts("left");
         if (buf[8] < 247) {
          puts("left");
          if (buf[9] < 24) {
           puts("left");
          } else {
           puts("right");
          }
         } else {
          puts("right");
          if (buf[9] < 146) {
           puts("left");
          } else {
           puts("right");
          }
         }
        } else {
         puts("right");
         if (buf[8] < 247) {
          puts("left");
          if (buf[9] < 73) {
           puts("left");
          } else {
           puts("right");
          }
         } else {
          puts("right");
          if (buf[9] < 54) {
           puts("left");
          } else {
           puts("right");
          }
         }
        }
       } else {
        puts("right");
        if (buf[7] < 90) {
         puts("left");
         if (buf[8] < 12) {
          puts("left");
          if (buf[9] < 56) {
           puts("left");
          } else {
           puts("right");
          }
         } else {
          puts("right");
          if (buf[9] < 252) {
           puts("left");
          } else {
           puts("right");
          }
         }
        } else {
         puts("right");
         if (buf[8] < 174) {
          puts("left");
          if (buf[9] < 21) {
           puts("left");
          } else {
           puts("right");
          }
         } else {
          puts("right");
          if (buf[9] < 95) {
           puts("left");
          } else {
           puts("right");
          }
         }
        }
       }
      } else {
       puts("right");
       if (buf[6] < 255) {
        puts("left");
        if (buf[7] < 94) {
         puts("left");
         if (buf[8] < 3) {
          puts("left");
          if (buf[9] < 137) {
           puts("left");
          } else {
           puts("right");
          }
         } else {
          puts("right");
          if (buf[9] < 50) {
           puts("left");
          } else {
           puts("right");
          }
         }
        } else {
         puts("right");
         if (buf[8] < 244) {
          puts("left");
          if (buf[9] < 239) {
           puts("left");
          } else {
           puts("right");
          }
         } else {
          puts("right");
          if (buf[9] < 89) {
           puts("left");
          } else {
           puts("right");
          }
         }
        }
       } else {
        puts("right");
        if (buf[7] < 20) {
         puts("left");
         if (buf[8] < 54) {
          puts("left");
          if (buf[9] < 54) {
           puts("left");
          } else {
           puts("right");
          }
         } else {
          puts("right");
          if (buf[9] < 134) {
           puts("left");
          } else {
           puts("right");
          }
         }
        } else {
         puts("right");
         if (buf[8] < 226) {
          puts("left");
          if (buf[9] < 45) {
           puts("left");
          } else {
           puts("right");
          }
         } else {
          puts("right");
          if (buf[9] < 103) {
           puts("left");
          } else {
           puts("right");
          }
         }
        }
       }
      }
     } else {
      puts("right");
      if (buf[5] < 207) {
       puts("left");
       if (buf[6] < 152) {
        puts("left");
        if (buf[7] < 142) {
         puts("left");
         if (buf[8] < 221) {
          puts("left");
          if (buf[9] < 16) {
           puts("left");
          } else {
           puts("right");
          }
         } else {
          puts("right");
          if (buf[9] < 61) {
           puts("left");
          } else {
           puts("right");
          }
         }
        } else {
         puts("right");
         if (buf[8] < 87) {
          puts("left");
          if (buf[9] < 65) {
           puts("left");
          } else {
           puts("right");
          }
         } else {
          puts("right");
          if (buf[9] < 68) {
           puts("left");
          } else {
           puts("right");
          }
         }
        }
       } else {
        puts("right");
        if (buf[7] < 2) {
         puts("left");
         if (buf[8] < 190) {
          puts("left");
          if (buf[9] < 43) {
           puts("left");
          } else {
           puts("right");
          }
         } else {
          puts("right");
          if (buf[9] < 74) {
           puts("left");
          } else {
           puts("right");
          }
         }
        } else {
         puts("right");
         if (buf[8] < 249) {
          puts("left");
          if (buf[9] < 169) {
           puts("left");
          } else {
           puts("right");
          }
         } else {
          puts("right");
          if (buf[9] < 33) {
           puts("left");
          } else {
           puts("right");
          }
         }
        }
       }
      } else {
       puts("right");
       if (buf[6] < 241) {
        puts("left");
        if (buf[7] < 211) {
         puts("left");
         if (buf[8] < 146) {
          puts("left");
          if (buf[9] < 111) {
           puts("left");
          } else {
           puts("right");
          }
         } else {
          puts("right");
          if (buf[9] < 234) {
           puts("left");
          } else {
           puts("right");
          }
         }
        } else {
         puts("right");
         if (buf[8] < 90) {
          puts("left");
          if (buf[9] < 70) {
           puts("left");
          } else {
           puts("right");
          }
         } else {
          puts("right");
          if (buf[9] < 114) {
           puts("left");
          } else {
           puts("right");
          }
         }
        }
       } else {
        puts("right");
        if (buf[7] < 136) {
         puts("left");
         if (buf[8] < 205) {
          puts("left");
          if (buf[9] < 56) {
           puts("left");
          } else {
           puts("right");
          }
         } else {
          puts("right");
          if (buf[9] < 34) {
           puts("left");
          } else {
           puts("right");
          }
         }
        } else {
         puts("right");
         if (buf[8] < 10) {
          puts("left");
          if (buf[9] < 185) {
           puts("left");
          } else {
           puts("right");
          }
         } else {
          puts("right");
          if (buf[9] < 103) {
           puts("left");
          } else {
           puts("right");
          }
         }
        }
       }
      }
     }
    }
   }
  }
 }
}