/*
 * Copyright (C) 2014 jsonwebtoken.io
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package io.jsonwebtoken.test;

import junit.framework.Assert;

import org.easymock.EasyMockSupport;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.robolectric.RobolectricTestRunner;
import org.robolectric.annotation.Config;

import io.jsonwebtoken.JwtHandlerAdapter;
import io.jsonwebtoken.UnsupportedJwtException;

@Config(manifest = "build/intermediates/manifests/debug/AndroidManifest.xml", resourceDir =
        "../../../../build/intermediates/res/debug", emulateSdk = 18)
@RunWith(RobolectricTestRunner.class)
public class JwtHandlerAdapterTest extends EasyMockSupport {

    JwtHandlerAdapter handler;

    @Before
    public void setup() {
        handler = new JwtHandlerAdapter();
    }

    @Test
    public void testOnPlaintextJwt() {
        try {
            handler.onPlaintextJwt(null);
            Assert.fail(); //shouldn't reach this point
        } catch (UnsupportedJwtException e) {
            Assert.assertEquals(e.getMessage(), "Unsigned plaintext JWTs are not supported.");
        }
    }

    @Test
    public void testOnClaimsJwt() {
        try {
            handler.onClaimsJwt(null);
            Assert.fail(); //shouldn't reach this point
        } catch (UnsupportedJwtException e) {
            Assert.assertEquals(e.getMessage(), "Unsigned Claims JWTs are not supported.");
        }
    }

    @Test
    public void testOnPlaintextJws() {
        try {
            handler.onPlaintextJws(null);
            Assert.fail(); //shouldn't reach this point
        } catch (UnsupportedJwtException e) {
            Assert.assertEquals(e.getMessage(), "Signed plaintext JWSs are not supported.");
        }
    }

    @Test
    public void testOnClaimsJws() {
        try {
            handler.onClaimsJws(null);
            Assert.fail(); //shouldn't reach this point
        } catch (UnsupportedJwtException e) {
            Assert.assertEquals(e.getMessage(), "Signed Claims JWSs are not supported.");
        }
    }
}
