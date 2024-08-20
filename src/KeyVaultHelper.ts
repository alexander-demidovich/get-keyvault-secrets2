import * as core from '@actions/core';
import { IAuthorizer } from 'azure-actions-webclient/Authorizer/IAuthorizer';
import { KeyVaultActionParameters } from "./KeyVaultActionParameters";
import { KeyVaultClient } from "./KeyVaultClient";
import { readFileSync } from 'fs';
import { sync as globSync } from 'glob';
import util = require("util");

export class AzureKeyVaultSecret {
    name: string;
    enabled: boolean;
    expires: Date | undefined;
    contentType: string;
}

export class KeyVaultHelper {

    private keyVaultActionParameters: KeyVaultActionParameters;
    private keyVaultClient: KeyVaultClient;

    constructor(handler: IAuthorizer, timeOut: number, keyVaultActionParameters: KeyVaultActionParameters) {
        this.keyVaultActionParameters = keyVaultActionParameters;
        this.keyVaultClient = new KeyVaultClient(handler, timeOut, keyVaultActionParameters.keyVaultUrl);
    }

    public async initKeyVaultClient(){
        await this.keyVaultClient.init();
    }

    public downloadSecrets(): Promise<void> {
        if (this.keyVaultActionParameters.secretsFilePath){
            let selectedSecrets = this.readKeyValuesFromFile(this.keyVaultActionParameters.secretsFilePath);
            return this.downloadSelectedSecrets(selectedSecrets);
        }

        if (this.keyVaultActionParameters.secretsFilter && this.keyVaultActionParameters.secretsFilter.length === 1 && this.keyVaultActionParameters.secretsFilter[0] === "*") {
             return this.downloadAllSecrets();
        } else {
            console.log(`Downloading selected secrets with filter: ${this.keyVaultActionParameters.secretsFilter}`);
            let selectedSecrets = this.readKeyValuesFromFilter(this.keyVaultActionParameters.secretsFilter);
            return this.downloadSelectedSecrets(selectedSecrets);
        }
    }

    private downloadAllSecrets(): Promise<void> {
        return new Promise<void>((resolve, reject) => {
            this.keyVaultClient.getSecrets("", (error, listOfSecrets) => {
                if (error) {
                    return reject(core.debug(util.format("Get Secrets Failed \n%s", this.getError(error))));
                }

                if (listOfSecrets.length == 0) {
                    core.debug(util.format("No secrets found in the vault %s", this.keyVaultActionParameters.keyVaultName))
                    return resolve();
                }

                console.log(util.format("Number of secrets found in keyvault %s: %s", this.keyVaultActionParameters.keyVaultName, listOfSecrets.length));
                listOfSecrets = this.filterDisabledAndExpiredSecrets(listOfSecrets);
                console.log(util.format("Number of enabled secrets found in keyvault %s: %s", this.keyVaultActionParameters.keyVaultName, listOfSecrets.length));
                
                var getSecretValuePromises: Promise<any>[] = [];
                listOfSecrets.forEach((secret: AzureKeyVaultSecret, index: number) => {
                    getSecretValuePromises.push(this.downloadSecretValue(secret.name, secret.name));
                });

                Promise.all(getSecretValuePromises).then(() => {
                    return resolve();
                });
            });
        });
    }

    private downloadSelectedSecrets(secretsMap: Map<string, string>): Promise<void> {
        return new Promise<void>((resolve, reject) => {
            var getSecretValuePromises: Promise<any>[] = [];
            secretsMap.forEach((secretName: string, secretEnv: string) => {
                console.log(util.format("Downloading secret %s", secretName));

                getSecretValuePromises.push(this.downloadSecretValue(secretName, secretEnv));
            });

            Promise.all(getSecretValuePromises).then(() => {
                return resolve();
            }, error => {
                return reject(new Error("Downloading selected secrets failed"));
            });
        });
    }

    private downloadSecretValue(secretName: string, secretEnv: string): Promise<any> {
        return new Promise<void>((resolve, reject) => {
            this.keyVaultClient.getSecretValue(secretName, (error, secretValue) => {
                if (error) {
                    console.log(util.format("Failed to download secret %s", secretName));
                    core.setFailed(util.format("Could not download the secret %s", secretName));
                }
                else {
                    console.log(util.format("Downloaded secret %s", secretName));
                    this.setVaultVariable(secretEnv, secretValue);
                }
                
                return resolve();
            });
        });
    }

    private setVaultVariable(secretName: string, secretValue: string): void {
        if (!secretValue) {
            return;
        }

        core.setSecret(secretValue);
        core.exportVariable(secretName, secretValue);
        core.setOutput(secretName, secretValue);
    }

    private filterDisabledAndExpiredSecrets(listOfSecrets: AzureKeyVaultSecret[]): AzureKeyVaultSecret[] {
        var result: AzureKeyVaultSecret[] = [];
        var now: Date = new Date();

        listOfSecrets.forEach((value: AzureKeyVaultSecret, index: number) => {
            if (value.enabled && (!value.expires || value.expires > now)) {
                result.push(value);
            }
        });
        
        return result;
    }

    private readKeyValuesFromFile(filePattern: string): Map<string, string> {
      const keyValueMap: Map<string, string> = new Map();
      console.log(`Reading key values from file pattern: ${filePattern}`);
      const filePaths = globSync(filePattern);
      console.log(`Found ${filePaths.length} files matching the pattern: ${filePattern}`);

      if (filePaths.length === 0){
        core.setFailed("No files found matching the pattern: " + filePattern);
      }

      for (const filePath of filePaths) {
        console.log(`Reading key values from file: ${filePath}`);
        const fileContent = readFileSync(filePath, 'utf8');
        const lines = fileContent.split(',');

        for (const line of lines) {
          const trimmedLine = line.trim();
          console.log(`Reading key values from line: ${trimmedLine}`);
          if (trimmedLine) {
            const [key, value] = trimmedLine.split('=');
            keyValueMap.set(key.trim(), value.trim());
          }
        }
      }

      return keyValueMap;
    }

    private readKeyValuesFromFilter(secretsFilter: string): Map<string, string> {
        const keyValueMap: Map<string, string> = new Map();
        const pairs = secretsFilter.split(',');
        for (const pair of pairs) {
            const [key, value] = pair.trim().split('=');
            keyValueMap.set(key.trim(), value.trim());
        }

        return keyValueMap;
    }

    private getError(error: any): any {
        core.debug(JSON.stringify(error));

        if (error && error.message) {
            return error.message;
        }

        return error;
    }
}