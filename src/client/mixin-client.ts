import merge from 'lodash.merge';
import type { AxiosInstance } from 'axios';
import { validate } from 'uuid';
import type Keystore from './types/keystore';
import type { HTTPConfig, RequestClient } from './types/client';
import { createAxiosClient, createRequestClient } from './utils/client';
import { AddressKeystoreClient } from './address';
import { AppKeystoreClient } from './app';
import { AssetKeystoreClient } from './asset';
import { AttachmentKeystoreClient } from './attachment';
import { CircleKeystoreClient } from './circle';
import { CodeKeystoreClient } from './code';
import { CollectibleKeystoreClient } from './collectible';
import { ConversationKeystoreClient } from './conversation';
import { ExternalKeystoreClient } from './external';
import { MessageKeystoreClient } from './message';
import { MultisigKeystoreClient } from './multisig';
import { NetworkBaseClient } from './network';
import { OAuthBaseClient } from './oauth';
import { PaymentBaseClient } from './payment';
import { PinKeystoreClient } from './pin';
import { RpcClient } from './rpc';
import { TransferKeystoreClient } from './transfer';
import { UserKeystoreClient } from './user';
import { WithdrawalKeystoreClient } from './withdrawal';
import { BlazeKeystoreClient } from './blaze';

const KeystoreClient = (axiosInstance: AxiosInstance, keystore: Keystore | undefined, config: HTTPConfig) => ({
  address: AddressKeystoreClient(axiosInstance, keystore),
  app: AppKeystoreClient(axiosInstance),
  asset: AssetKeystoreClient(axiosInstance),
  blaze: BlazeKeystoreClient(keystore, config.blazeOptions),
  attachment: AttachmentKeystoreClient(axiosInstance),
  circle: CircleKeystoreClient(axiosInstance),
  code: CodeKeystoreClient(axiosInstance),
  collection: CollectibleKeystoreClient(axiosInstance, keystore),
  conversation: ConversationKeystoreClient(axiosInstance, keystore),
  external: ExternalKeystoreClient(axiosInstance),
  message: MessageKeystoreClient(axiosInstance, keystore),
  multisig: MultisigKeystoreClient(axiosInstance, keystore),
  network: NetworkBaseClient(axiosInstance),
  oauth: OAuthBaseClient(axiosInstance),
  payment: PaymentBaseClient(axiosInstance),
  pin: PinKeystoreClient(axiosInstance, keystore),
  rpc: RpcClient(config),
  transfer: TransferKeystoreClient(axiosInstance, keystore),
  user: UserKeystoreClient(axiosInstance),
  withdrawal: WithdrawalKeystoreClient(axiosInstance, keystore),
});

export type KeystoreClientReturnType = ReturnType<typeof KeystoreClient>;

export function MixinApi(config: HTTPConfig = {}): KeystoreClientReturnType & RequestClient {
  const axiosInstance = createAxiosClient(config);
  const requestClient = createRequestClient(axiosInstance);

  const { keystore } = config;
  if (keystore && !keystore.user_id && keystore.client_id && validate(keystore.client_id)) 
    keystore.user_id = keystore.client_id;
    
  const keystoreClient = KeystoreClient(axiosInstance, keystore, config);

  return merge(keystoreClient, requestClient);
}
