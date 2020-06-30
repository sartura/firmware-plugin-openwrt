/**
 * @file upgrade.h
 * @author Mislav Novakovic <mislav.novakovic@sartur.hr>
 * @brief header file for upgrade.c
 *
 * @copyright
 * Copyright (C) 2017 Deutsche Telekom AG.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *	http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef UPGRADE_H
#define UPGRADE_H

#include "firmware.h"

bool compare_firmware_checksum(plugin_ctx_t *, firmware_t *);
int download_firmware(plugin_ctx_t *);
int install_firmware(plugin_ctx_t *);

#endif /* UPGRADE_H */
