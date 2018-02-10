package com.bbles.kerberos.server.utils;


import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import sun.security.krb5.KrbException;
import sun.security.krb5.internal.KDCRep;
import sun.security.krb5.internal.KDCReq;


/**
 * I used the TCP as the base of the communication(we could move the code to work Datagram packet instead (for more
 * performance).
 *
 *
 * We could also change the code to use Selector + Channel + UDP to enhance the code, but I prefered to used simple code
 * for the moment to check that the library is working.
 */
public class KDCServer implements Runnable {

  private ServerSocket server = null;
  private int poolLength = 4;

  public KDCServer(int port, int _poolLength) throws IOException {
    server = new ServerSocket(port);
    poolLength = _poolLength;
  }

  public KDCServer() throws IOException {
    server = new ServerSocket(88);
    poolLength = 10;
  }

  public KDCReq getReq(byte[] bytes, int req_type) throws KrbException, IOException {
    return new KDCReq(bytes, req_type);
  }

  /**
   * Check if the request is valid => Correct user => Correct keys
   */
  public boolean isValid(KDCReq request) {
    return true
  }

  /**
   * Not yet finished (should add all the checking parts)
   */
  public void run() {
    InputStream is = null;
    OutputStream os = null;
    Socket s = null;
    try {
      try {
        s = server.accept();
        is = s.getInputStream();
        byte[] req = new byte[is.available()];
        is.read(req);
        KDCReq kdcReq = getReq(req, 12);
        KDCRep kdcRep = new KDCRep(kdcReq.asn1EncodeReqBody(), 23);
        os.write(kdcRep.asn1Encode());
      } catch (KrbException e) {
        System.err.println("Unable to Answer the request because of : " + e.getMessage());
      } finally {
        is.close();
        os.close();
        s.close();
      }
    } catch (IOException e) {
      System.err.println("Unable to response to the request due to : " + e.getMessage());
    }

  }

  public int getPoolLength() {
    return poolLength;
  }

}