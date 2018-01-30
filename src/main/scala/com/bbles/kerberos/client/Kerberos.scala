package com.bbles.kerberos.client

object Kerberos {
  def main(argvs: Array[String]): Unit = {
    KerberosUtils.kinit(argvs, "Kerberos")
  }
}
