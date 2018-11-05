// Copyright (c) .NET Foundation. All rights reserved.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using NuGet.Versioning;
using Xunit;

namespace NuGet.Protocol.Tests
{
    public class PackageDetailsUriResourceV3Tests
    {
        [Theory]
        [InlineData("https://ex/packages/{id}/{version}", "https://ex/packages/Test/1.0.0-ALPHA")]
        [InlineData("https://ex/packages/{id}", "https://ex/packages/Test")]
        [InlineData("https://ex/packages/{version}", "https://ex/packages/1.0.0-ALPHA")]
        [InlineData("https://ex/packages", "https://ex/packages")]
        public void GetUriOrNullReplacesIdAndVersionTokensInUriTemplateWhenAvailable(string template, string expected)
        {
            var resource = PackageDetailsUriResourceV3.CreateOrNull(template);

            var actual = resource.GetUriOrNull("Test", NuGetVersion.Parse("1.0.0.0-ALPHA+git"));

            Assert.Equal(expected, actual.ToString());
        }
    }
}