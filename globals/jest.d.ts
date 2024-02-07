/* eslint-disable @typescript-eslint/naming-convention */
/* eslint-disable @typescript-eslint/consistent-type-definitions */
import type {
  Component,
  EnumToUnion,
  NotificationType,
} from '@metamask/snaps-sdk';

declare global {
  namespace jest {
    interface AsymmetricMatchers {
      toRespondWith(response: unknown): void;
      toRespondWithError(error: unknown): void;
      toSendNotification(
        message: string,
        type?: EnumToUnion<NotificationType>,
      ): void;
      toRender(component: Component): void;
    }
    interface Matchers<R> {
      toRespondWith(response: unknown): R;
      toRespondWithError(error: unknown): R;
      toSendNotification(
        message: string,
        type?: EnumToUnion<NotificationType>,
      ): R;
      toRender(component: Component): R;
    }
  }
}
