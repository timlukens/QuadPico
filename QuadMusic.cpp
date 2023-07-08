//QuadMusic.c
//
// Music and whatever

#include <stdlib.h>
#include <stdio.h>
#include <math.h>

#include "QuadMusic.h"

#define TWO_POW_ONE_TWELVE 1.059463094359
#define C_ZERO 16.35

static double freq_from_note_number(int note)
{
    return C_ZERO * pow(TWO_POW_ONE_TWELVE, (double)note);
}

QuadMusic::QuadMusic()
{
    mAcceptableFreqs = (double*)malloc(sizeof(double) * MAX_MUSICAL_NOTES);
    if(!mAcceptableFreqs)
    {
        //out of memory?
        while(1);
    }

    mNumAcceptableFreqs = 0;
    for(int i = 0; i < MAX_MUSICAL_NOTES; i++)
    {
        //Create a pentatonic scale
        int num = i % 12;
        if(num == 0 || num == 2 || num == 4 || num == 7 || num == 9)
        {
            mAcceptableFreqs[mNumAcceptableFreqs] = freq_from_note_number(i);
            mNumAcceptableFreqs++;
        }
    }
}

//fit an incoming frequency to a value from our acceptable frequencies (pentatonic scale)
double QuadMusic::FitFreqToAcceptableFreq(double freq)
{
    double foundFreq = 0;

    for(int i = 0; i < mNumAcceptableFreqs; i++)
    {
        if(freq < mAcceptableFreqs[i]) break;
        foundFreq = mAcceptableFreqs[i];
    }

    return foundFreq;
}