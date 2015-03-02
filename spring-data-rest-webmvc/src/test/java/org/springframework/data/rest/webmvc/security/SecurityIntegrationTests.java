/*
 * Copyright 2014 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.springframework.data.rest.webmvc.security;

import static org.hamcrest.Matchers.*;
import static org.junit.Assert.*;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

import java.util.Arrays;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.rest.webmvc.AbstractWebIntegrationTests;
import org.springframework.hateoas.config.EnableHypermediaSupport;
import org.springframework.http.HttpStatus;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.access.intercept.aopalliance.MethodSecurityInterceptor;
import org.springframework.security.authentication.AuthenticationCredentialsNotFoundException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.context.WebApplicationContext;
import org.springframework.web.util.NestedServletException;

/**
 * Test Spring Data REST in the context of being locked down by Spring Security. Uses MockMvc to simulate HTTP-based
 * interactions. Testing is also possible on the repository level, but that doesn't align with the mission
 * of Spring Data REST.
 *
 * @author Greg Turnquist
 * @author Rob Winch
 */
@RunWith(SpringJUnit4ClassRunner.class)
@ContextConfiguration(classes = {SecureJpaConfiguration.class, SecurityConfiguration.class})
@Transactional
@EnableHypermediaSupport(type = EnableHypermediaSupport.HypermediaType.HAL)
public class SecurityIntegrationTests extends AbstractWebIntegrationTests {

	@Autowired WebApplicationContext context;
	@Autowired MethodSecurityInterceptor methodSecurityInterceptor;

	@Autowired SecuredPersonRepository personRepository;
	@Autowired PreAuthorizedOrderRepository orderRepository;

	@Before
	public void preloadData() {

		SecurityContextHolder.getContext().setAuthentication(new UsernamePasswordAuthenticationToken("user", "user",
				AuthorityUtils.createAuthorityList("ROLE_USER", "ROLE_ADMIN")));

		personRepository.deleteAll();
		orderRepository.deleteAll();

		Person frodo = personRepository.save(new Person("Frodo", "Baggins"));
		orderRepository.save(new Order(frodo));

		SecurityContextHolder.clearContext();
	}

	//=================================================================

	@Test
	public void deletePersonAccessDeniedForNoCredentials() throws Exception {

		// Getting the collection is not tested here. This is to get the URI that will later be tested for DELETE
		MockHttpServletResponse response = mvc.perform(get(client.discoverUnique("people").expand().getHref()).//
				with(user("user").roles("USER"))).//
				andReturn().getResponse();
		String href = assertHasJsonPathValue("$..self.href[0]", response);

		SecurityContextHolder.clearContext();

		try {
			mvc.perform(delete(href));
			fail("Delete should fail with no credentials");
		} catch (NestedServletException e) {
			assertThat(e.getCause(), instanceOf(AuthenticationCredentialsNotFoundException.class));
		}
	}

	@Test
	public void deletePersonAccessDeniedForUsers() throws Exception {

		MockHttpServletResponse response = mvc.perform(get(client.discoverUnique("people").expand().getHref()).//
				with(user("user").roles("USER"))).//
				andReturn().getResponse();
		String href = assertHasJsonPathValue("$..self.href[0]", response);

		try {
			mvc.perform(delete(href).with(user("user").roles("USER")));
			fail("Delete should fail with these credentials");
		} catch (NestedServletException e) {
			assertThat(e.getCause(), instanceOf(AccessDeniedException.class));
		}
	}

	@Test
	public void deletePersonAccessGrantedForAdmins() throws Exception {


		MockHttpServletResponse response = mvc.perform(get(client.discoverUnique("people").expand().getHref()).//
				with(user("user").roles("USER", "ADMIN"))).//
				andReturn().//
				getResponse();
		String href = assertHasJsonPathValue("$..self.href[0]", response);

		SecurityContextHolder.clearContext();

		mvc.perform(delete(href).with(user("user").roles("USER", "ADMIN")))
			.andExpect(status().is(HttpStatus.NO_CONTENT.value()));
	}

	//=================================================================

	@Test
	public void findAllPeopleAccessDeniedForNoCredentials() throws Throwable {

		try {
			client.request(client.discoverUnique("people"));
			fail("GET people should fail with no credentials");
		} catch (NestedServletException e) {
			assertThat(e.getCause(), instanceOf(AuthenticationCredentialsNotFoundException.class));
		}
	}

	@Test
	public void findAllPeopleAccessGrantedForUsers() throws Throwable {

		mvc.perform(get(client.discoverUnique("people").expand().getHref()).with(user("user").roles("USER")))
			.andExpect(status().isOk());
	}

	@Test
	public void findAllPeopleAccessGrantedForAdmins() throws Throwable {

		mvc.perform(get(client.discoverUnique("people").expand().getHref()).with(user("user").roles("USER", "ADMIN")))
				.andExpect(status().isOk());
	}

	//=================================================================


	@Test
	public void deleteOrderAccessDeniedForNoCredentials() throws Exception {

		// Getting the collection is not tested here. This is to get the URI that will later be tested for DELETE
		MockHttpServletResponse response = mvc.perform(get(client.discoverUnique("orders").expand().getHref()).//
				with(user("user").roles("USER"))).//
				andReturn().getResponse();
		String href = assertHasJsonPathValue("$..self.href[0]", response);

		// Clear any side effects of logging into get the URI from security.
		SecurityContextHolder.clearContext();

		try {
			mvc.perform(delete(href));
			fail("Delete should fail with no credentials");
		} catch (NestedServletException e) {
			assertThat(e.getCause(), instanceOf(AuthenticationCredentialsNotFoundException.class));
		}
	}

	@Test
	public void deleteOrderAccessDeniedForUsers() throws Exception {

		MockHttpServletResponse response = mvc.perform(get(client.discoverUnique("orders").expand().getHref()).//
				with(user("user").roles("USER"))).//
				andReturn().getResponse();
		String href = assertHasJsonPathValue("$..self.href[0]", response);

		try {
			mvc.perform(delete(href).with(user("user").roles("USER")));
			fail("Delete should fail with these credentials");
		} catch (NestedServletException e) {
			assertThat(e.getCause(), instanceOf(AccessDeniedException.class));
		}
	}

	@Test
	public void deleteOrderAccessGrantedForAdmins() throws Exception {

		MockHttpServletResponse response = mvc.perform(get(client.discoverUnique("orders").expand().getHref()).//
				with(user("user").roles("USER"))).//
				andReturn().//
				getResponse();
		String href = assertHasJsonPathValue("$..self.href[0]", response);

		// Clear any side effects of logging into get the URI from security.
		SecurityContextHolder.clearContext();

		mvc.perform(delete(href).with(user("user").roles("USER", "ADMIN")))
				.andExpect(status().is(HttpStatus.NO_CONTENT.value()));
	}

	//=================================================================

	@Test
	public void findAllOrdersAccessDeniedForNoCredentials() throws Throwable {

		try {
			client.request(client.discoverUnique("orders"));
			fail("GET people should fail with no credentials");
		} catch (NestedServletException e) {
			assertThat(e.getCause(), instanceOf(AuthenticationCredentialsNotFoundException.class));
		}
	}

	@Test
	public void findAllOrdersAccessGrantedForUsers() throws Throwable {

		mvc.perform(get(client.discoverUnique("orders").expand().getHref()).with(user("user").roles("USER")))
				.andExpect(status().isOk());
	}

	@Test
	public void findAllOrdersAccessGrantedForAdmins() throws Throwable {

		mvc.perform(get(client.discoverUnique("orders").expand().getHref()).with(user("user").roles("USER", "ADMIN")))
				.andExpect(status().isOk());
	}

}
