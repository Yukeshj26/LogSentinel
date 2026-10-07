package com.forensics.loganalyzer.storage;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface LogEntryRepository extends JpaRepository<PersistedLogEntry, Long> {

    List<PersistedLogEntry> findTop100ByOrderByTimestampDesc();

    List<PersistedLogEntry> findTop500ByOrderByTimestampDesc();

    List<PersistedLogEntry> findTop50ByIpAddressOrderByTimestampDesc(String ipAddress);

    List<PersistedLogEntry> findTop50ByUsernameOrderByTimestampDesc(String username);

    long countByIpAddress(String ipAddress);

    long countByUsername(String username);

    long countByStatusCodeIn(List<String> statuses);
}
