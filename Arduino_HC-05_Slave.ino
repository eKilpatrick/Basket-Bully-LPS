#include <SoftwareSerial.h>
#include <math.h>
#include "string.h"
#include <Servo.h>
Servo myservo;

//servo pin
#define servoPin 6
//distance from anchor 1 to anchor 2 where the basketball goal is in the center
#define lengthC 12

SoftwareSerial BTSerial(2,3); // RX, TX pins of HC-05

int prevServoAngle = 0;

void setup() {
  Serial.begin(38400);
  BTSerial.begin(38400);

  myservo.attach(servoPin);
}

void loop() {
  if (BTSerial.available()) {
    String BTString = BTSerial.readStringUntil(">");
    while(BTSerial.available()) {BTSerial.read();}
    double distA = BTString.substring(1,6).toDouble();
    double distB = BTString.substring(7,11).toDouble();

      //subtract from 180 to get the other angle since the servo is flipped
      double angle = 180.0 - (CalculateAngle(distA, distB, lengthC) * 180 / PI);

      Serial.print(BTString);
      Serial.print("  ");

      Serial.print("Angle computed: ");
      Serial.println(angle);
      //Add code here to move the servo to the proper direction
      //int stepSize = abs(angle - prevServoAngle) / 5;
      //for (int i = prevServoAngle; i <= angle; i += stepSize) {
      //  myservo.write(i);
      //  delay(100);
      //}
      //prevServoAngle = angle;
      
      
      if (abs(angle-prevServoAngle) > 5) {
        Serial.println("   Moving Servo");
        myservo.write(angle);
      }
      prevServoAngle = angle;
  }
}

double CalculateAngle(double a, double b, double c) {
  //STEP 1: Calculate angle B
  double B = acos((pow(a, 2) + pow(c, 2) - pow(b, 2)) / (2 * a * c));

  //STEP 2: Calculate length b2 = distance of person from the goal
  double b2 = sqrt(pow(a, 2) + pow((c/2), 2) - 2 * a * (c/2) * cos(B));

  //STEP 3: Calculate mid-angle A = angle of person to the goal
  double A = acos((pow(b2, 2) + pow((c/2), 2) - pow(a, 2)) / (2 * b2 * (c/2)));

  return A;
}