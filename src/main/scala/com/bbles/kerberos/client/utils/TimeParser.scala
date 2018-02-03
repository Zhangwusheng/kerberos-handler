package com.bbles.kerberos.client.utils

import java.util.Date

import sun.security.krb5.internal.KerberosTime

case class TimeParser(time: String) {
  private[this] def r(c: Char) = s"""\d+$c""".r

  /**
    * Parse the hour value from the string time
    *
    * @return hour value in int
    */
  private[this] def getHour: Int = r('h').findFirstIn(time).getOrElse("0").toInt


  /**
    * Pase the minutes value from the string time
    *
    * @return
    */
  private[this] def getMin: Int = r('m').findFirstIn(time).getOrElse("0").toInt


  /**
    * Parse the second value from the string time
    *
    * @return
    */
  private[this] def getSec: Int = r('s').findFirstIn(time).getOrElse("0").toInt


  /**
    * Convert the `time` duration to timestamp
    * TODO: I'm not sure if this method is optimized (as it's also for many other functions)
    *
    * @return
    */
  private[this] def toTimeStamp: Long = (new Date).getTime + (new Date(0, 0, 0, getHour, getMin, getSec)).getTime

  /**
    * Generate a kerberosTime
    *
    * @return
    */
  def toKerberosTime: KerberosTime = new KerberosTime(toTimeStamp)
}