//QuadMusic.h
//
// Helper functions and a class for music shenanigans

#define MAX_MUSICAL_NOTES 120

static double freq_from_note_number(int note);

class QuadMusic
{
public:
    QuadMusic();

    double FitFreqToAcceptableFreq(double freq);

private:
    double *mAcceptableFreqs;
    int mNumAcceptableFreqs;
};