#include <stdio.h>

#include "PwmIn.h"
#include "PwmIn.pio.h"

PwmIn::PwmIn(uint input)
{
    // pio 0 is used
    pio = pio0;
    // state machine 0
    sm = 0;
    // configure the used pins
    pio_gpio_init(pio, input);
    // load the pio program into the pio memory
    uint offset = pio_add_program(pio, &PwmIn_program);
    // make a sm config
    pio_sm_config c = PwmIn_program_get_default_config(offset);
    // set the 'jmp' pin
    sm_config_set_jmp_pin(&c, input);
    // set shift direction
    sm_config_set_in_shift(&c, false, false, 0);
    // init the pio sm with the config
    pio_sm_init(pio, sm, offset, &c);
    // enable the sm
    pio_sm_set_enabled(pio, sm, true);
}

// read_period (in seconds)
float PwmIn::read_period(void)
{
    if (read() == -1)
    {
        return -1;
    }
    // one clock cycle is 1/125000000 seconds
    return (period * 0.000000008);
}

// read_pulsewidth (in seconds)
float PwmIn::read_pulsewidth(void)
{
    if (read() == -1)
    {
        return -1;
    }
    // one clock cycle is 1/125000000 seconds
    return (pulsewidth * 0.000000008);
}

// read_dutycycle (between 0 and 1)
float PwmIn::read_dutycycle(void)
{
    if (read() == -1)
    {
        return -1;
    }
    return ((float)pulsewidth / (float)period);
}

// read the period and pulsewidth
float PwmIn::read(void)
{
    int timeout = 0;
    // clear the FIFO: do a new measurement
    pio_sm_clear_fifos(pio, sm);
    // wait for the FIFO to contain two data items: pulsewidth and period
    while (pio_sm_get_rx_fifo_level(pio, sm) < 2)
    {
        timeout++;
        if(timeout>500000) break;
    }
    // read pulse width from the FIFO
    uint32_t t1 = (0xFFFFFFFF - pio_sm_get(pio, sm));
    // read period from the FIFO
    uint32_t t2 = (0xFFFFFFFF - pio_sm_get(pio, sm));
    // since data is continuously added to the FIFO, sometimes the period/pulse data is read reversed
    if (t1 > t2)
    {
        period = t1;
        pulsewidth = t2;
    }
    else
    {
        period = t2;
        pulsewidth = t1;
    }
    // the measurements are taken with 2 clock cycles per timer tick
    pulsewidth = 2 * pulsewidth;
    // calculate the period in clock cycles:
    period = 2 * period;
    // return as successful
    return 0;
}