package me.synology.hajubal.springsecurity.security.service;

import lombok.Data;
import me.synology.hajubal.springsecurity.domain.entity.Account;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.User;

import java.util.List;

@Data
public class AccountContext extends User {
  private Account account;

  public AccountContext(Account account, List<GrantedAuthority> roles) {
    super(account.getUsername(), account.getPassword(), roles);
    this.account = account;
  }
}
