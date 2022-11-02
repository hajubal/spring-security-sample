package me.synology.hajubal.springsecurity.security.service;

import lombok.*;
import me.synology.hajubal.springsecurity.domain.dto.AccountDto;
import me.synology.hajubal.springsecurity.domain.entity.Account;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.User;

import java.util.List;



@Getter
@Setter
@ToString
@EqualsAndHashCode
@Value
public class AccountContext extends User {
  private AccountDto account;

  public AccountContext(AccountDto account, List<GrantedAuthority> roles) {
    super(account.getUsername(), account.getPassword(), roles);
    this.account = account;
  }
}
