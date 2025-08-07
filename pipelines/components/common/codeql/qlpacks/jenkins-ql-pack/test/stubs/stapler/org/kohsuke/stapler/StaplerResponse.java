/*
 * Copyright (c) 2004-2010, Kohsuke Kawaguchi
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without modification, are permitted provided
 * that the following conditions are met:
 *
 *     * Redistributions of source code must retain the above copyright notice, this list of
 *       conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright notice, this list of
 *       conditions and the following disclaimer in the documentation and/or other materials
 *       provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS
 * OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA,
 * OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER
 * IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF
 * THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

package org.kohsuke.stapler;

import net.sf.json.JsonConfig;
import org.kohsuke.stapler.export.ExportConfig;
import org.kohsuke.stapler.export.Flavor;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.Writer;
import java.net.URL;

public interface StaplerResponse extends HttpServletResponse {

    void forward(Object it, String url, StaplerRequest request) throws ServletException, IOException;

    void forwardToPreviousPage(StaplerRequest request) throws ServletException, IOException;

    void sendRedirect2(String url) throws IOException;

    void sendRedirect(int statusCore, String url) throws IOException;

    void serveFile(StaplerRequest request, URL res) throws ServletException, IOException;

    void serveFile(StaplerRequest request, URL res, long expiration) throws ServletException, IOException;

    void serveLocalizedFile(StaplerRequest request, URL res) throws ServletException, IOException;

    void serveLocalizedFile(StaplerRequest request, URL res, long expiration) throws ServletException, IOException;

    void serveFile(StaplerRequest req, InputStream data, long lastModified, long expiration, long contentLength, String fileName) throws ServletException, IOException;

    void serveFile(StaplerRequest req, InputStream data, long lastModified, long expiration, int contentLength, String fileName) throws ServletException, IOException;

    void serveFile(StaplerRequest req, InputStream data, long lastModified, long contentLength, String fileName) throws ServletException, IOException;

    void serveFile(StaplerRequest req, InputStream data, long lastModified, int contentLength, String fileName) throws ServletException, IOException;

    @Deprecated
    void serveExposedBean(StaplerRequest req, Object exposedBean, Flavor flavor) throws ServletException,IOException;

    default void serveExposedBean(StaplerRequest req, Object exposedBean, ExportConfig exportConfig) throws ServletException,IOException {
        serveExposedBean(req, exposedBean, exportConfig.getFlavor());
    }

    OutputStream getCompressedOutputStream(HttpServletRequest req) throws IOException;

    Writer getCompressedWriter(HttpServletRequest req) throws IOException;

    int reverseProxyTo(URL url, StaplerRequest req) throws IOException;

    void setJsonConfig(JsonConfig config);

    JsonConfig getJsonConfig();
}