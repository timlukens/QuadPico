//Buggy.cpp
//
// Buggy class is mostly a rewrite of the micropython code supplied by Kitronik Autonomous Robotics Platform
// Some modifications were made to make better use of the C++ Pico SDK

#include "Buggy.h"
#include <stdio.h>
#include "hardware/pwm.h"
#include "pico/time.h"
#include "pico/stdlib.h"
#include "hardware/irq.h"
#include "PWMHelper.h"
#include "FreeRTOS.h"
#include "task.h"
#include "PwmIn.h"
#include "myHardware.h"

static double distanceReadout = 0;

//Task called by FreeRTOS task system
//We want this to constantly be updating our distanceReadout variable so we can poll it at any time.
void distanceTask(void *pvParameters)
{
    Buggy *bug = (Buggy*)pvParameters;
    double unitConversionFactor = 0.0343;

    while(1)
    {
        gpio_put(US_TRIGGER_PIN, 0);
        sleep_us(2);
        gpio_put(US_TRIGGER_PIN, 1);
        sleep_us(5);
        gpio_put(US_TRIGGER_PIN, 0);

        float echo_in_seconds = bug->usEchoRead->read_pulsewidth();
        double echo_in_us = echo_in_seconds * 100000.0;

        distanceReadout = (echo_in_us * unitConversionFactor) / 2.0;
        sleep_ms(1);
    }
}

Buggy::Buggy()
{
    printf("Buggy init\n");

    //init motor pins as PWMs
    gpio_set_function(MOTOR_1_PIN, GPIO_FUNC_PWM);
    gpio_set_function(MOTOR_1_BACKWARDS_PIN, GPIO_FUNC_PWM);
    gpio_set_function(MOTOR_2_PIN, GPIO_FUNC_PWM);
    gpio_set_function(MOTOR_2_BACKWARDS_PIN, GPIO_FUNC_PWM);


    //Set default pwm config across each pin
    pwm_config config = pwm_get_default_config();
    pwm_config_set_clkdiv(&config, 1.f);

    uint slice_num = pwm_gpio_to_slice_num(MOTOR_1_PIN);
    pwm_init(slice_num, &config, true);

    slice_num = pwm_gpio_to_slice_num(MOTOR_1_BACKWARDS_PIN);
    pwm_init(slice_num, &config, true);

    slice_num = pwm_gpio_to_slice_num(MOTOR_2_PIN);
    pwm_init(slice_num, &config, true);

    slice_num = pwm_gpio_to_slice_num(MOTOR_2_BACKWARDS_PIN);
    pwm_init(slice_num, &config, true);

    //init ultra-sonic sensor (trigger emitter/echo receiver)
    gpio_init(US_TRIGGER_PIN);
    gpio_set_dir(US_TRIGGER_PIN, GPIO_OUT);

    gpio_init(US_ECHO_PIN);
    gpio_set_dir(US_ECHO_PIN, GPIO_IN);

    //This object is used to determine the pulse width of our echo pin
    //which is just how long it is digital high
    usEchoRead = new PwmIn(US_ECHO_PIN);

    //Used to convert our raw pulse width to centimeters
    unitConversionFactor = 0.0343;
    maxDistanceTimeout = int( 2 * 500 / unitConversionFactor);

    xTaskCreate(
        distanceTask,    // Task to be run
        "Distance Task", // Name of the Task for debugging and managing its Task Handle
        1024,        // Stack depth to be allocated for use with task's stack (see docs)
        this,        // Arguments needed by the Task (NULL because we don't have any)
        2,           // Task Priority - Higher the number the more priority [max is (configMAX_PRIORITIES - 1) provided in FreeRTOSConfig.h]
        NULL         // Task Handle if available for managing the task
    );
}

Buggy::~Buggy()
{

}

void Buggy::motorOn(int motor, int direction, int speed)
{
    int gpio = -1;
    int gpioOpposite = -1;
    switch(motor)
    {
    case MOTOR_L:
        gpio = MOTOR_1_PIN;
        gpioOpposite = MOTOR_1_BACKWARDS_PIN;
        if(direction == MOTOR_BACKWARD) 
        {
            gpio = MOTOR_1_BACKWARDS_PIN;
            gpioOpposite = MOTOR_1_PIN;
        }
        break;

    case MOTOR_R:
        gpio = MOTOR_2_PIN;
        gpioOpposite = MOTOR_2_BACKWARDS_PIN;
        if(direction == MOTOR_BACKWARD) 
        {
            gpio = MOTOR_2_BACKWARDS_PIN;
            gpioOpposite = MOTOR_2_PIN;
        }
    }

    if(gpio == -1)
    {
        printf("Invalid motor number: %d", motor);
    }

    if(speed > 100) speed = 100;
    if(speed < 0) speed = 0;

    //start up the motor in the proper direction
    uint slice_num = pwm_gpio_to_slice_num(gpio);
    uint chan = pwm_gpio_to_channel(gpio);
    pwm_set_freq_duty(slice_num, chan, 100, speed);

    //turn off the other direction (forward/backward)
    slice_num = pwm_gpio_to_slice_num(gpioOpposite);
    chan = pwm_gpio_to_channel(gpioOpposite);
    pwm_set_freq_duty(slice_num, chan, 100, 0);
}

void Buggy::motorOff(int motor)
{
    motorOn(motor, MOTOR_FORWARD, 0);
    motorOn(motor, MOTOR_BACKWARD, 0);
}

double Buggy::getDistance()
{
    return distanceReadout;
}