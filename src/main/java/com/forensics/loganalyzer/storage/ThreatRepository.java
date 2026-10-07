package com.forensics.loganalyzer.storage;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface ThreatRepository extends JpaRepository<PersistedThreat, Long> {

    List<PersistedThreat> findTop100ByOrderByDetectedAtDesc();

    List<PersistedThreat> findAllByOrderByDetectedAtDesc();

    List<PersistedThreat> findByIpAddressOrderByDetectedAtDesc(String ipAddress);

    List<PersistedThreat> findByUsernameOrderByDetectedAtDesc(String username);
}
