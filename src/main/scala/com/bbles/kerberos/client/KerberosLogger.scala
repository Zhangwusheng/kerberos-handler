package com.bbles.kerberos.client

import org.slf4j.LoggerFactory
import org.apache.log4j.PropertyConfigurator


trait KerberosLogger extends {
  a =>


  PropertyConfigurator.configure("/Users/m.benalla/workspace/bbles/kerberos5/kerberos/src/main/resources/log4j2.properties")
  var DEBUG: Boolean = true

  val logger = LoggerFactory.getLogger(a.getClass.getSimpleName)

  def debug(str: String) = logger.debug(str)
}
