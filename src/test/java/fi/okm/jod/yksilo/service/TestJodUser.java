/*
 * Copyright (c) 2024 The Finnish Ministry of Education and Culture, The Finnish
 * The Ministry of Economic Affairs and Employment, The Finnish National Agency of
 * Education (Opetushallitus) and The Finnish Development and Administration centre
 * for ELY Centres and TE Offices (KEHA).
 *
 * Licensed under the EUPL-1.2-or-later.
 */

package fi.okm.jod.yksilo.service;

import fi.okm.jod.yksilo.domain.JodUser;
import java.util.UUID;

record TestJodUser(UUID id) implements JodUser {

  @Override
  public UUID getId() {
    return id();
  }

  static JodUser of(String uuid) {
    return new TestJodUser(UUID.fromString(uuid));
  }
}
