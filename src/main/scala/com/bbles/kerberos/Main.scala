package com.bbles.kerberos

import java.io.File

import com.bbles.kerberos.client.KerberosLogger
import sun.security.krb5.Config

object Main extends KerberosLogger {
  def main(argvs: Array[String]): Unit = {
    val config = Config.getInstance
    val realm = "test"
    //   val app = Class.forName("com.bbles.kerberos.client.Kerberos")
    //    val kinit = app.getDeclaredMethod("kinit", new Array[String](1).getClass)
    //    System.setProperty("http.proxyHost", "someHost")
    //   System.setProperty("java.security.krb5.realm", "someHost")
    System.exit(exec("com.bbles.kerberos.client.Kerberos"))
  }


  def exec(className: String): Int = {
    val javaHome = System.getProperty("java.home")
    val javaBin = javaHome + File.separator + "bin" + File.separator + "java"
    val classpath = System.getProperty("java.class.path")
    val builder = new ProcessBuilder(javaBin, "-Djava.security.krb5.kdc=localhost","-Djava.security.krb5.realm=localhost", "-cp", classpath, className,
      "--principal=m.benalla",
      "--password=test", "--debug", "--cachename=krb5cc_ele")
    builder.redirectOutput(new File("output.out"))
    builder.redirectError(new File("error.out"))
    val process = builder.start
    debug("get result")
    process.waitFor()
    return process.exitValue
  }
}