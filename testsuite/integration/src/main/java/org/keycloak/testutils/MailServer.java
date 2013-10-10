package org.keycloak.testutils;

import javax.mail.internet.MimeMessage;
import javax.mail.internet.MimeMessage.RecipientType;

import com.icegreen.greenmail.util.GreenMail;
import com.icegreen.greenmail.util.ServerSetup;

public class MailServer {

    public static void main(String[] args) throws Exception {
        ServerSetup setup = new ServerSetup(3025, "localhost", "smtp");

        GreenMail greenMail = new GreenMail(setup);
        greenMail.start();
        
        while (true) {
            int c = greenMail.getReceivedMessages().length;

            if (greenMail.waitForIncomingEmail(Long.MAX_VALUE, c + 1)) {
                MimeMessage message = greenMail.getReceivedMessages()[c++];
                System.out.println("Received mail to " + message.getRecipients(RecipientType.TO)[0]);
                System.out.println();
                System.out.println(message.getContent());
                System.out.println("-------------------------------------------------------");
            }
        }
    }

}
