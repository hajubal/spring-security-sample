package me.synology.hajubal.springsecurity.service;

import me.synology.hajubal.springsecurity.domain.dto.AccountDto;
import me.synology.hajubal.springsecurity.domain.entity.Account;

import java.util.List;

public interface UserService {

    void createUser(Account account);

    void modifyUser(AccountDto accountDto);

    List<Account> getUsers();

    AccountDto getUser(Long id);

    void deleteUser(Long idx);
}
