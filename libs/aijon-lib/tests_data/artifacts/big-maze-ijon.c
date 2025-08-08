// The maze demo is taken from Felipe Andres Manzano's blog:
// http://feliam.wordpress.com/2010/10/07/the-symbolic-maze/
//
//

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <assert.h>
#include <stdbool.h>

#define H 13
#define W 17

char maze[H][W]={
"+-+-------------+",
"| |             |", 
"| | +-----* *---+",
"|   |           |",
"+---+-* *-------+",
"|               |",
"+ +-------------+",
"| |       |   |#|",
"| | *---+ * * * |",
"| |     |   |   |",
"| +---* +-------+",
"|               |",
"+---------------+",};

void draw ()
{
        int i, j;
        for (i = 0; i < H; i++)
          {
                  for (j = 0; j < W; j++)
                                  printf ("%c", maze[i][j]);
                  printf ("\n");
          }
        printf ("\n");
}

int
main (int argc, char *argv[])
{
        int x, y;     //Player position
        int ox, oy;   //Old player position
        int i = 0;    //Iteration number
#define ITERS 512
        char program[ITERS];
        x = 1;
        y = 1;
        maze[y][x]='X';
        draw();
        read(0,program,ITERS);
        IJON_CTX(0); // Initial state
        while(i < ITERS)
        {
                IJON_SET(i); // Track progress through iterations
                IJON_SET(x * 100 + y); // Track unique positions in the maze

#ifndef MAZE_NO_BT
                maze[y][x]=' ';
#endif
                ox = x;    //Save old player position
                oy = y;
    //transition(hashint(x,y));
                IJON_CTX(x * 100 + y); // Track state based on current position
                switch (program[i])
                {
                        case 'w':
                                IJON_CTX(1); // Track movement direction
                                y--;
                                break;
                        case 's':
                                IJON_CTX(2);
                                y++;
                                break;
                        case 'a':
                                IJON_CTX(3);
                                x--;
                                break;
                        case 'd':
                                IJON_CTX(4);
                                x++;
                                break;
                        default:
                                printf("Wrong command!(only w,s,a,d accepted!)\n");
                                printf("You lose!\n");
                                exit(-1);
                }
                // Track distance to goal
                IJON_DIST(abs(y - 7) + abs(x - 15), 0); // Manhattan distance to goal at [7][15]

                if (maze[y][x] == '#')
                {
                        IJON_CTX(999); // Found the goal!
      assert(0);
                }
                IJON_CMP(maze[y][x], ' '); // Guide towards valid moves
                if (maze[y][x] != ' ') {
                        x = ox;
                        y = oy;
                }
#ifdef MAZE_NO_BT
                if (ox==x && oy==y){
                        printf("You lose\n");
                        exit(-2);
                }
#endif

                maze[y][x]='X';
                draw ();          //draw it
                IJON_MAX(i); // Maximize progress through the maze
                i++;
        }
        printf("You lose\n");
}