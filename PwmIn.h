#ifndef __PWMIN__
#define __PWMIN__

#include <stdlib.h>

#include "pico/stdlib.h"
#include "hardware/pio.h"



class PwmIn
{
public:
    PwmIn(uint input);
    float read_period(void);
    float read_pulsewidth(void);
    float read_dutycycle(void);

private:
    float read(void);

    // the pio instance
    PIO pio;
    // the state machine
    uint sm;
    // data about the PWM input measured in pio clock cycles
    uint32_t pulsewidth, period;
};

#endif