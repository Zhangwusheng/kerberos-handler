package com.bbles.kerberos.server

import java.io.IOException

import com.bbles.kerberos.server.utils.KDCServer

object KDC extends App {
  def start(): Unit = {
    try {
      var kdc = new KDCServer
      for (i <- 1 until kdc.getPoolLength)
        new Thread(kdc).start()
    }
    catch {
      case exception: IOException =>
        System.err.println("Unable to start the KDC because of : " + exception.getMessage)
    }
  }
}
