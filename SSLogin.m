#import <UIKit/UIKit.h>
#import <Foundation/Foundation.h>

// Host calls this on the main thread with its visible view controller.
__attribute__((visibility("default")))
void SSLoginPresent(UIViewController *host, void (^completion)(BOOL)) {
    if (!host) { if (completion) completion(NO); return; }
    UIAlertController *alert = [UIAlertController alertControllerWithTitle:@"SS LOGIN" message:@"Enter your KeyVault license key. Your device identifier will be sent for verification." preferredStyle:UIAlertControllerStyleAlert];
    alert.overrideUserInterfaceStyle = UIUserInterfaceStyleDark;
    alert.view.tintColor = [UIColor colorWithRed:0.70 green:0.96 blue:0.29 alpha:1];
    [alert addTextFieldWithConfigurationHandler:^(UITextField *f) { f.placeholder = @"License key"; f.autocorrectionType = UITextAutocorrectionTypeNo; f.autocapitalizationType = UITextAutocapitalizationTypeNone; f.secureTextEntry = YES; }];
    [alert addAction:[UIAlertAction actionWithTitle:@"Cancel" style:UIAlertActionStyleCancel handler:^(__unused UIAlertAction *a) { if (completion) completion(NO); }]];
    __weak UIAlertController *weakAlert = alert;
    [alert addAction:[UIAlertAction actionWithTitle:@"Verify access" style:UIAlertActionStyleDefault handler:^(__unused UIAlertAction *a) {
        NSString *key = [weakAlert.textFields.firstObject.text stringByTrimmingCharactersInSet:NSCharacterSet.whitespaceAndNewlineCharacterSet];
        NSString *hwid = UIDevice.currentDevice.identifierForVendor.UUIDString;
        if (!key.length || !hwid.length) { if (completion) completion(NO); return; }
        NSMutableURLRequest *request = [NSMutableURLRequest requestWithURL:[NSURL URLWithString:@"https://onestate-key-compass.lovable.app/api/public/check"]];
        request.HTTPMethod = @"POST"; request.timeoutInterval = 20;
        [request setValue:@"application/json" forHTTPHeaderField:@"Content-Type"];
        request.HTTPBody = [NSJSONSerialization dataWithJSONObject:@{@"key":key,@"hwid":hwid} options:0 error:NULL];
        [[[NSURLSession sharedSession] dataTaskWithRequest:request completionHandler:^(NSData *data, NSURLResponse *response, NSError *error) {
            NSInteger status = [response isKindOfClass:NSHTTPURLResponse.class] ? [(NSHTTPURLResponse *)response statusCode] : 0;
            id json = data ? [NSJSONSerialization JSONObjectWithData:data options:0 error:NULL] : nil;
            id valid = [json isKindOfClass:NSDictionary.class] ? json[@"valid"] : nil;
            BOOL ok = !error && status >= 200 && status < 300 && valid && CFGetTypeID((__bridge CFTypeRef)valid) == CFBooleanGetTypeID() && [valid boolValue];
            dispatch_async(dispatch_get_main_queue(), ^{ if (completion) completion(ok); });
        }] resume];
    }]];
    [host presentViewController:alert animated:YES completion:nil];
}
