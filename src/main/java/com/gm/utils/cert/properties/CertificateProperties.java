package com.gm.utils.cert.properties;

import javax.validation.constraints.Max;
import javax.validation.constraints.Min;

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
public class CertificateProperties {
    @Min(value = 1)
    @Max(value = 10)
    private int validityInYear;
    private String fileName;
    private String phrase;
}
