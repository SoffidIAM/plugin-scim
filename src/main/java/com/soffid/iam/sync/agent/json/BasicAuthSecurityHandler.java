package com.soffid.iam.sync.agent.json;

import org.apache.wink.client.ClientAuthenticationException;
import org.apache.wink.client.ClientRequest;
import org.apache.wink.client.ClientResponse;
import org.apache.wink.client.handlers.AbstractAuthSecurityHandler;
import org.apache.wink.client.handlers.ClientHandler;
import org.apache.wink.client.handlers.HandlerContext;
import org.apache.wink.common.http.HttpStatus;
import org.apache.wink.common.internal.i18n.Messages;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class BasicAuthSecurityHandler extends AbstractAuthSecurityHandler implements ClientHandler {

    private static Logger    logger       = LoggerFactory.getLogger(BasicAuthSecurityHandler.class);

    private static final int UNAUTHORIZED = HttpStatus.UNAUTHORIZED.getCode();

    public BasicAuthSecurityHandler() {
        /* do nothing */
    }

    public BasicAuthSecurityHandler(final String username, final String password) {
        super(username, password);
    }

    /**
     * Performs basic HTTP authentication and proxy authentication, if
     * necessary.
     * 
     * @param client request object
     * @param handler context object
     * @return a client response object that may contain an HTTP Authorization
     *         header
     */
    public ClientResponse handle(ClientRequest request, HandlerContext context) throws Exception {
        logger.trace("Entering BasicAuthSecurityHandler.doChain()"); //$NON-NLS-1$
        if (!(handlerUsername == null || handlerUsername.equals("") || handlerPassword == null || handlerPassword.equals(""))) { //$NON-NLS-1$ //$NON-NLS-2$
            logger.trace("userid and password set so setting Authorization header"); //$NON-NLS-1$
            // we have a user credential
            if (handlerEncodedCredentials == null) {
                handlerEncodedCredentials = getEncodedString(handlerUsername, handlerPassword);
            }
            request.getHeaders()
                .putSingle("Authorization", handlerEncodedCredentials); //$NON-NLS-1$
            logger.trace("Issuing request again with Authorization header"); //$NON-NLS-1$
            return context.doChain(request);
        } else {
            return context.doChain(request);
        }
    }

}
