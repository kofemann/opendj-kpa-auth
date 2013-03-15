/*
 * Author: Landon Fuller <landonf@mac68k.info>
 *
 * Copyright (c) 2013 Landon Fuller <landonf@mac68k.info>
 * All rights reserved.
 */

package coop.plausible.opendj.plugin.kpa;

import com.sun.security.auth.module.Krb5LoginModule;
import org.opends.messages.Message;
import org.opends.server.api.AuthenticationPolicy;
import org.opends.server.api.AuthenticationPolicyState;
import org.opends.server.loggers.debug.DebugTracer;
import org.opends.server.types.*;

import javax.security.auth.Subject;
import javax.security.auth.callback.*;
import javax.security.auth.kerberos.KerberosPrincipal;
import javax.security.auth.login.*;
import java.io.IOException;
import java.security.Principal;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;


import static org.opends.server.loggers.ErrorLogger.logError;

import static org.opends.server.loggers.debug.DebugLogger.debugEnabled;
import static org.opends.server.loggers.debug.DebugLogger.getTracer;

/**
 * Kerberos authentication policy state.
 */
class KerberosPolicyState extends AuthenticationPolicyState {
    /** The parent kerberos policy. */
    private final KerberosPolicy policy;
    
    private final DebugTracer TRACER = getTracer();

    /**
     * Create a new policy state instance.
     *
     * @param policy The parent kerberos policy.
     * @param userEntry The user entry to be managed.
     */
    public KerberosPolicyState (KerberosPolicy policy, Entry userEntry) {
        super(userEntry);
        this.policy = policy;
    }

    @Override
    public AuthenticationPolicy getAuthenticationPolicy () {
        return policy;
    }

    @Override
    public boolean passwordMatches (final ByteString byteString) throws DirectoryException {
        /**
         * It's not possible to authenticate an arbitrary principal if this system property
         * is set, as it will override the principal we provide below.
         */
        if (System.getProperty("sun.security.krb5.principal") != null) {
            logError(Message.fromObject("The 'sun.security.krb5.principal' system property is set. This will override all " +
                "the authentication principal when performing Kerberos pass-through authentication."));
            return false;
        }

        /* Kerberos module options */
        final Map<String,Object> options = new HashMap<String, Object>();
        options.put("refreshKrb5Config", "true"); // Fetch most up-to-date configuration
        options.put("useTicketCache", "true"); // Do not reference the hosts' ticket cache
        options.put("doNotPrompt", "true"); // Fetch principal et al from the shared state
        options.put("useFirstPass", "true"); // Use auth info from the shared state, do not retry

        options.put("debug", "true");

        /* Kerberos module state */
        final Map<String,Object> state = new HashMap<String, Object>();
        state.put("javax.security.auth.login.name", "landonf@EXAMPLE.ORG" /* TODO!!! */);
        state.put("javax.security.auth.login.password", byteString.toString().toCharArray());

        /* Create the noop handler */
        CallbackHandler cbh = new CallbackHandler() {
            @Override
            public void handle (Callback[] callbacks) throws IOException, UnsupportedCallbackException {
                for (Callback callback : callbacks) {
                    throw new UnsupportedCallbackException(callback, "Unrecognized Callback " + callback);
                }
            }
        };

        /* Instantiate the login context */
        final Krb5LoginModule loginModule = new Krb5LoginModule();
        loginModule.initialize(new Subject(), cbh, state, options);
        try {
            loginModule.login();
            loginModule.logout();
        } catch (FailedLoginException e) {
            if (debugEnabled()) {
                TRACER.debugCaught(DebugLogLevel.INFO, e);
            }
            return false;
        } catch (LoginException e) {
            logError(Message.fromObject("Failed to issue Kerberos login request: " + e.getMessage()));
            if (debugEnabled()) {
                TRACER.debugCaught(DebugLogLevel.ERROR, e);
            }

            return false;
        }

        return true;
    }
}
