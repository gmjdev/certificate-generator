package com.gm.utils.cert.properties;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import lombok.ToString;

@Getter
@Setter
@ToString
@NoArgsConstructor
@AllArgsConstructor
public class SanEntries {
    private String orgDomain;
    private boolean includeWildCardDomain;
    private boolean includeLocalHost;
    private boolean includeWildCardLocalHost;
}
