package com.bbles.kerberos.client.utils

import sun.security.krb5.Config

import scala.collection.mutable


/**
  * Override sun.security.krb5.Config to support many kind of operations:
  *   - Personalized KDCs for a given realm.
  */
class Configuration extends Config {
  private[this] val kdcConfig: mutable.Map[String, String] = mutable.Map[String, String]()


  /**
    * Get the list of KDCs to Contact to get tgs
    *
    * @param s : Realm name
    * @return : List of KDCS
    */
  override def getKDCList(s: String): String = {
    if (kdcConfig.getOrElse(s, "").isEmpty)
      super.getKDCList(s)
    else
      kdcConfig.getOrElse(s, "")
  }

  /**
    * Override the configuration of the list of the kdc
    *
    * @param realm    : The realm
    * @param kdclists : An array of lists of KDCs, every KDCs should have the format
    *                 host:port
    */
  def setKDC(realm: String, kdclists: Array[String]): Unit = {
    kdcConfig.update(realm, kdclists.reduce((a, b) => a + ", " + b))
  }
}
