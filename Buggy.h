#include <stdlib.h>
#include "PwmIn.h"

class Buggy
{
public:
    Buggy();
    ~Buggy();

    void motorOn(int motor, int direction, int speed);
    void motorOff(int motor);

    double getDistance();

    PwmIn *usEchoRead;

private:
    double unitConversionFactor;
    int maxDistanceTimeout;
};